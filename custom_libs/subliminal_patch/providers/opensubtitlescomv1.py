# -*- coding: utf-8 -*-
import logging
import os
import time

from requests import Session
from subzero.language import Language

from babelfish import language_converters
from subliminal import Episode, Movie
from subliminal.score import get_equivalent_release_groups
from subliminal.utils import sanitize_release_group, sanitize
from subliminal.exceptions import ConfigurationError, ServiceUnavailable, ProviderError
from .mixins import ProviderRetryMixin
from subliminal_patch.subtitle import Subtitle
from subliminal.subtitle import fix_line_ending
from subliminal_patch.providers import Provider
from subliminal_patch.subtitle import guess_matches
from guessit import guessit

logger = logging.getLogger(__name__)


class OpenSubtitlesComV1Subtitle(Subtitle):
    provider_name = 'opensubtitlescomv1'
    hash_verifiable = True
    hearing_impaired_verifiable = True

    def __init__(self, language, forced, hearing_impaired, page_link, file_id, releases, uploader, title, year,
                 hash_matched, file_hash=None, season=None, episode=None, imdb_match=False):
        super().__init__(language, hearing_impaired, page_link)
        language = Language.rebuild(language, hi=hearing_impaired, forced=forced)

        self.title = title
        self.year = year
        self.season = season
        self.episode = episode
        self.releases = releases
        self.release_info = releases
        self.language = language
        self.hearing_impaired = hearing_impaired
        self.forced = forced
        self.file_id = file_id
        self.page_link = page_link
        self.download_link = None
        self.uploader = uploader
        self.matches = None
        self.hash = file_hash
        self.encoding = 'utf-8'
        self.hash_matched = hash_matched
        self.imdb_match = imdb_match

    @property
    def id(self):
        return self.file_id

    def get_matches(self, video):
        matches = set()
        type_ = "movie" if isinstance(video, Movie) else "episode"

        # handle movies and series separately
        if type_ == "episode":
            # series
            matches.add('series')
            # season
            if video.season == self.season:
                matches.add('season')
            # episode
            if video.episode == self.episode:
                matches.add('episode')
            # imdb
            if self.imdb_match:
                matches.add('series_imdb_id')
        else:
            # title
            matches.add('title')
            # imdb
            if self.imdb_match:
                matches.add('imdb_id')

        # rest is same for both groups

        # year
        if video.year == self.year:
            matches.add('year')

        # release_group
        if (video.release_group and self.releases and
                any(r in sanitize_release_group(self.releases)
                    for r in get_equivalent_release_groups(sanitize_release_group(video.release_group)))):
            matches.add('release_group')

        if self.hash_matched:
            matches.add('hash')

        # other properties
        matches |= guess_matches(video, guessit(self.releases, {"type": type_}))

        self.matches = matches

        return matches


class OpenSubtitlesComV1Provider(ProviderRetryMixin, Provider):
    """OpenSubtitles.com API v1 Provider with API Key Authentication"""
    server_url = 'https://api.opensubtitles.com/api/v1'

    # Map custom language codes
    custom_languages = {
        'pt': 'pt-PT',
        'zh': 'zh-CN',
        'es-MX': 'ea',
    }

    languages = ({Language.fromietf("es-MX")} |
                 {Language.fromopensubtitles(lang) for lang in language_converters['szopensubtitles'].codes})
    languages.update(set(Language.rebuild(lang, forced=True) for lang in languages))
    languages.update(set(Language.rebuild(lang, hi=True) for lang in languages))

    video_types = (Episode, Movie)

    def __init__(self, api_key=None, use_hash=True):
        if not api_key:
            raise ConfigurationError('API key must be specified')

        self.session = Session()
        self.session.headers = {
            'User-Agent': os.environ.get("SZ_USER_AGENT", "Infuse"),
            'Api-Key': api_key,
            'Content-Type': 'application/json',
            'Accept': '*/*'
        }
        self.api_key = api_key
        self.video = None
        self.use_hash = use_hash

    def initialize(self):
        pass

    def terminate(self):
        self.session.close()

    @staticmethod
    def to_opensubtitles_lang(lang):
        """Convert language code to OpenSubtitles format"""
        if lang in OpenSubtitlesComV1Provider.custom_languages:
            return OpenSubtitlesComV1Provider.custom_languages[lang]
        return lang

    @staticmethod
    def from_opensubtitles_lang(lang):
        """Convert OpenSubtitles language code to standard format"""
        reverse_map = {v: k for k, v in OpenSubtitlesComV1Provider.custom_languages.items()}
        if lang in reverse_map:
            return reverse_map[lang]
        return lang

    @staticmethod
    def sanitize_external_ids(external_id):
        """Sanitize IMDB ID"""
        if isinstance(external_id, str):
            external_id = external_id.lower().lstrip('tt').lstrip('0')
        sanitized_id = external_id[:-1].lstrip('0') + external_id[-1]
        return int(sanitized_id)

    @staticmethod
    def is_real_forced(attributes):
        """Check if subtitle is truly forced (foreign parts only)"""
        return attributes.get('foreign_parts_only', False) and not attributes.get('hearing_impaired', False)

    def query(self, languages, video):
        self.video = video

        # Prepare parameters based on video type
        params = {}

        # Add language filter
        langs_list = sorted(list(set([self.to_opensubtitles_lang(lang.basename).lower() for lang in languages])))
        params['languages'] = ','.join(langs_list)

        # Add IMDB ID if available
        if isinstance(video, Episode) and video.series_imdb_id:
            imdb_id = self.sanitize_external_ids(video.series_imdb_id)
            params['imdb_id'] = imdb_id
            params['season_number'] = video.season
            params['episode_number'] = video.episode
        elif isinstance(video, Movie) and video.imdb_id:
            imdb_id = self.sanitize_external_ids(video.imdb_id)
            params['imdb_id'] = imdb_id

        # Add hash if available and enabled
        if self.use_hash and hasattr(video, 'hashes'):
            file_hash = video.hashes.get('opensubtitlescom')
            if file_hash:
                params['moviehash'] = file_hash
                logger.debug(f'Searching using hash: {file_hash}')

        if not params.get('imdb_id') and not params.get('moviehash'):
            logger.debug('No IMDB ID or hash available for search')
            return []

        logger.debug(f'Searching subtitles with params: {params}')

        # Query the server
        try:
            response = self.retry(
                lambda: self.session.get(
                    f'{self.server_url}/subtitles',
                    params=params,
                    timeout=30
                ),
                amount=3
            )
            response.raise_for_status()
            result = response.json()
        except Exception as e:
            logger.error(f'Error querying OpenSubtitles API: {e}')
            raise ServiceUnavailable(f'Error querying OpenSubtitles API: {e}')

        subtitles = []

        if 'data' not in result:
            logger.debug('No data in response')
            return subtitles

        # Filter forced subtitles based on requested languages
        data = result['data']
        if all([lang.forced for lang in languages]):  # only forced
            data = [x for x in data if self.is_real_forced(x.get('attributes', {}))]
        elif not any([lang.forced for lang in languages]):  # not forced
            data = [x for x in data if not self.is_real_forced(x.get('attributes', {}))]

        logger.debug(f"Query returned {len(data)} subtitles")

        for item in data:
            attributes = item.get('attributes', {})

            # Skip AI translated subtitles
            if attributes.get('ai_translated', False):
                logger.debug("Skipping AI translated subtitle")
                continue

            # Skip machine translated subtitles
            if attributes.get('machine_translated', False):
                logger.debug("Skipping machine translated subtitle")
                continue

            # Extract subtitle information
            feature_details = attributes.get('feature_details', {})
            season_number = feature_details.get('season_number')
            episode_number = feature_details.get('episode_number')
            moviehash_match = attributes.get('moviehash_match', False)

            try:
                year = int(feature_details.get('year'))
            except (TypeError, ValueError):
                year = feature_details.get('year')

            files = attributes.get('files', [])
            if not files:
                continue

            subtitle = OpenSubtitlesComV1Subtitle(
                language=Language.fromietf(self.from_opensubtitles_lang(attributes.get('language', 'en'))),
                forced=self.is_real_forced(attributes),
                hearing_impaired=attributes.get('hearing_impaired', False),
                page_link=attributes.get('url', ''),
                file_id=files[0].get('file_id'),
                releases=attributes.get('release', ''),
                uploader=attributes.get('uploader', {}).get('name', 'anonymous'),
                title=feature_details.get('movie_name', ''),
                year=year,
                season=season_number,
                episode=episode_number,
                hash_matched=moviehash_match,
                imdb_match=bool(params.get('imdb_id'))
            )
            subtitle.get_matches(video)
            subtitles.append(subtitle)

        return subtitles

    def list_subtitles(self, video, languages):
        return self.query(languages, video)

    def download_subtitle(self, subtitle):
        logger.info('Downloading subtitle %r', subtitle)

        # Request download link
        try:
            response = self.retry(
                lambda: self.session.post(
                    f'{self.server_url}/download',
                    json={'file_id': subtitle.file_id, 'sub_format': 'srt'},
                    timeout=30
                ),
                amount=3
            )
            response.raise_for_status()
            download_data = response.json()
            subtitle.download_link = download_data.get('link')
        except Exception as e:
            logger.error(f'Error requesting download link: {e}')
            raise ProviderError(f'Error requesting download link: {e}')

        if not subtitle.download_link:
            logger.error('No download link in response')
            subtitle.content = None
            return

        # Download subtitle content
        try:
            response = self.retry(
                lambda: self.session.get(subtitle.download_link, timeout=30),
                amount=3
            )
            response.raise_for_status()
            subtitle.content = fix_line_ending(response.content)
        except Exception as e:
            logger.error(f'Error downloading subtitle from {subtitle.download_link}: {e}')
            subtitle.content = None

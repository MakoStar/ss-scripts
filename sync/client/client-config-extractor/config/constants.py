#!/usr/bin/env python3
import json
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass

_ROOT_CONFIG = json.loads(
    (Path(__file__).resolve().parents[4] / "config.json").read_text(encoding="utf-8")
)
_GLOBAL = _ROOT_CONFIG["GLOBAL"]


@dataclass
class SettingMap:
    tag: str
    salt: str
    api_url: str
    pkg_url: str
    gl_ver: str = "game_latest_version"
    gl_path: str = "game_latest_file_path"
    api_route: str = _GLOBAL["GAME_CONFIG"]
    api_params: str = _GLOBAL["LAUNCHER_API_PARAMS"]


RegionSettings = Enum(
    "RegionSettings",
    {
        region: SettingMap(
            tag=_ROOT_CONFIG[region]["TAG"],
            salt=_ROOT_CONFIG[region]["SALT"],
            api_url=_ROOT_CONFIG[region]["API_URL"],
            pkg_url=_ROOT_CONFIG[region]["PKG_URL"],
        )
        for region in _ROOT_CONFIG["REGIONS"]
    },
)


def get_launcher_version(region: str) -> str:
    return _ROOT_CONFIG[region]["LAUNCHER_VERSION"]


class ProjectConfigs:
    IS_SAVE_MANIFEST: bool           = False
    REGION_KEYS: List[str]           = [r.name for r in RegionSettings]
    ROOT_OUTPUT_PATH: str            = "./output"
    OUTPUT_DATA_PATH_TPL: str        = "output/{region}/"
    INPUT_METADATA_PATH_TPL: str     = "./data_storage/metadatas/{region}/"
    SAVE_RESOURCE_PATH: str          = "./data_storage/data_u3d/{tag}/"
    SAVE_MANIFEST_JSON_PATH: str     = "./data_storage/manifests/{tag}/manifest.json"
    NEED_FETCHER_RESOURCES: Set[str] = {"data.unity3d"}
    VERSION_OUTPUT: str              = "./output/version.json"


class FileRuleConfigs:
    EXT_BIN: str    = ".bin"
    EXT_JSON: str   = ".json"
    EXT_LUA: str    = ".lua"
    EXT_BYTES: str  = ".bytes"
    EXT_ARCX: str   = ".arcx"
    EXT_ARCH: str   = ".arch"
    EXT_HTML: str   = ".html"
    EXT_TEXT: str   = ".txt"

    EXT_UPDATE_MANIFEST: str = ".ss_win.mani"



class RequestConfigs:
    TOTAL: int                  = 3
    VERIFY: bool                = False
    BACKOFF_FACTOR: int         = 1
    RAISE_ON_STATUS: bool       = True
    TIMEOUT: Tuple[int, int]    = (15, 60)
    ALLOWED_METHODS: List[str]  = ["GET", "POST"]
    STATUS_FORCELIST: List[int] = [429, 500, 502, 503, 504]


@dataclass
class ExportFileItem:
    type_name: str
    file_name: str
    extension: str
    parse_method: str


class AssetTypes:
    TEXT_ASSET: str = "TextAsset"
    MONO_BEHAVIOUR: str = "MonoBehaviour"


class ExtractorSettings:
    ASSET_NAME: str = "data.unity3d"
    NEED_EXPORT_FILES: List[ExportFileItem] = [
        ExportFileItem(
            file_name="SDKConfigSettings", 
            parse_method="parse_as_object",
            type_name=AssetTypes.TEXT_ASSET, 
            extension=FileRuleConfigs.EXT_JSON    
        ),
        ExportFileItem(
            file_name="ClientConfig", 
            parse_method="get_raw_data",
            type_name=AssetTypes.MONO_BEHAVIOUR, 
            extension=FileRuleConfigs.EXT_BYTES    
        )
    ]

class ClientConfigParserSettings:
    ALIGNMENT: int = 4
    TARGET_NAME = b"ClientConfig"
    MAX_BACKTRACK_OFFSET: int = 100
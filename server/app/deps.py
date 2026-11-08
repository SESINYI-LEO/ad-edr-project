from fastapi import Request

from .ad import Directory
from .config import Settings, get_settings
from .detection import Detector


def directory(request: Request) -> Directory:
    return request.app.state.directory


def detector(request: Request) -> Detector:
    return request.app.state.detector


def settings() -> Settings:
    return get_settings()

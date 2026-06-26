"""backend/app/config.py"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    abuseipdb_key: str = ""
    greynoise_key: str = ""          # community API key — gratis di greynoise.io
    censys_api_token: str = ""       # Personal Access Token dari search.censys.io → avatar → Personal Access Tokens
    # ip-api.com tidak butuh key (free tier 45 req/menit)
    port: int = 8090
    cors_origins: list[str] = ["http://localhost:3001", "https://threat.yohanesfc.web.id"]

    model_config = {"env_file": ".env", "extra": "ignore"}

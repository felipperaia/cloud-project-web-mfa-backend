from motor.motor_asyncio import AsyncIOMotorClient
from .config import settings

client = AsyncIOMotorClient(settings.MONGODB_URI, uuidRepresentation="standard")
db = client.get_default_database()
users = db["users"]
temp_tokens = db["temp_tokens"]  # para MFA challenge JWT blacklist opcional / single-use

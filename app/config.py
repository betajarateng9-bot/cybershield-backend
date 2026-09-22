import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

if SECRET_KEY is None:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Create a .env file in the Backend folder with SECRET_KEY=your-key-here."
    )
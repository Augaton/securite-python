import os

from tp2.utils.config import logger

if __name__ == "__main__":
    logger.info(f"OpenAI key: {os.getenv('OPENAI_KEY')}")

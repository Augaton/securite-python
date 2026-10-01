import logging

from dotenv import load_dotenv

load_dotenv()


def get_log_handlers() -> list[logging.Handler]:
    """
    Logs dans app.log et dans la console, ou seulement dans la console si app.log ne peut pas être créé
    (dossier courant en lecture seule dans le bac à sable de correction)
    """
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    try:
        handlers.insert(0, logging.FileHandler("app.log", mode="a"))
    except OSError:
        pass
    return handlers


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=get_log_handlers(),
)

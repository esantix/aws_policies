import logging
import colorlog


class Logger:
    @staticmethod
    def get_logger(name):

        color_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(funcName)s:%(levelname)s%(reset)s: %(message)s',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',

            },
            reset=True
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(color_formatter)

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        if not logger.hasHandlers():
            logger.addHandler(console_handler)

        return logger

# logger_config.py
import logging
import colorlog

class LoggerConfig:
    @staticmethod
    def get_logger(name):
        # Define a color formatter for different log levels
        color_formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(levelname)s:%(reset)s %(message)s',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
            },
            reset=True  # Reset color after each message
        )

        # Create a console handler and set the formatter
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(color_formatter)

        # Create a logger object
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        if not logger.hasHandlers():
            logger.addHandler(console_handler)

        return logger
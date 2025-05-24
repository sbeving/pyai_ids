# --- IMPORTANT: Add this block to any file in a subdirectory if you run it directly ---
import sys
import os

# Get the path to the project root (pyai_ids directory)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- END IMPORTANT BLOCK ---
import logging
import sys
import os
import configparser

def get_log_level_from_config():
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), '..', 'configs', 'config.ini')

    # Fallback to current directory if running from a test script in utils or similar
    if not os.path.exists(config_path):
        config_path_alt = 'configs/config.ini' # Assumes running from pyai_ids root
        if os.path.exists(config_path_alt):
             config_path = config_path_alt
        else:
            print(f"Warning: Config file not found at {config_path} or {config_path_alt}. Defaulting log level to INFO.")
            return logging.INFO # Default if config is truly not found


    try:
        config.read(config_path)
        log_level_str = config.get('General', 'log_level', fallback='INFO').upper()
        level = getattr(logging, log_level_str, logging.INFO)
        return level
    except Exception as e:
        print(f"Error reading log level from config: {e}. Defaulting to INFO.")
        return logging.INFO

def setup_logger(name='pyai_ids_logger', log_file='app.log', level=None):
    """Function to setup as many loggers as you want"""
    # Ensure logs directory exists relative to project root
    logs_dir = os.path.join(project_root, 'logs')
    if not os.path.exists(logs_dir):
        try:
            os.makedirs(logs_dir)
        except OSError as e:
            print(f"Error creating logs directory {logs_dir}: {e}. Logging to current directory.")
            # Fallback for log_file path if logs directory can't be created
            log_full_path = log_file # Just use the base name
    else:
        log_full_path = os.path.join(logs_dir, log_file)


    if level is None:
        level = get_log_level_from_config()

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # File handler
    try:
        file_handler = logging.FileHandler(log_full_path)
        file_handler.setFormatter(formatter)
    except Exception as e:
        print(f"Error setting up file handler for {log_full_path}: {e}. File logging disabled.")
        file_handler = None

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to prevent duplicates if re-running in interactive sessions
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    if file_handler:
        logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Prevent propagation to root logger, which can cause duplicate messages
    logger.propagate = False

    return logger

app_logger = setup_logger()

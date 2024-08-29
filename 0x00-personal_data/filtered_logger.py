#!/usr/bin/env python3
"""
Module for filtering log messages and securely connecting to a database.
"""

import re  # Import regular expressions module.
import os  # Import os module to access environment variables.
import logging  # Import logging module for handling log messages.
import mysql.connector  # Import MySQL connector for database connection.
from typing import List  # Import List for type hinting.

PII_FIELDS = ("name", "email", "phone", "ssn", "password")  # Fields considered PII.


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Obfuscate sensitive information in a log message.

    Args:
        fields (List[str]): The list of fields to obfuscate.
        redaction (str): The string to replace the field values with.
        message (str): The log message to be filtered.
        separator (str): The separator character separating fields in the log message.

    Returns:
        str: The obfuscated log message.
    """
    # Create a regex pattern to match fields to be obfuscated
    pattern = r'({})=([^{}]*)'.format('|'.join(fields), separator)
    
    # Use 're.sub' to replace the matched patterns with the redaction string
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class for log message formatting with obfuscation. """

    REDACTION = "***"  # The string to replace sensitive data with.
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"  # The separator between different fields in log messages.

    def __init__(self, fields: List[str]):
        """
        Initialize RedactingFormatter with fields to obfuscate.

        Args:
            fields (List[str]): The list of fields to obfuscate in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record, obfuscating specified fields.

        Args:
            record (logging.LogRecord): The log record to format.

        Returns:
            str: The formatted and obfuscated log message.
        """
        # Apply the 'filter_datum' function to obfuscate sensitive fields in the log message.
        return filter_datum(self.fields, self.REDACTION, super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Returns a logger configured to handle PII obfuscation.

    Returns:
        logging.Logger: A logger configured to handle sensitive data.
    """
    # Create and configure the logger
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Create a stream handler and attach the custom formatter
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(stream_handler)
    
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the MySQL database.

    Returns:
        mysql.connector.connection.MySQLConnection: A connector to the MySQL database.
    """
    # Retrieve environment variables for database credentials
    db_user = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    db_password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    db_host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    # Connect to the MySQL database using the retrieved credentials
    return mysql.connector.connect(
        user=db_user,
        password=db_password,
        host=db_host,
        database=db_name
    )


def main():
    """
    Main function that retrieves rows from the 'users' table in the database,
    filters the data, and displays it.
    """
    # Connect to the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    # Get field names from the database cursor
    fields = [field[0] for field in cursor.description]

    # Get the logger
    logger = get_logger()

    # Process each row, format, and log
    for row in cursor:
        message = "; ".join(f"{fields[i]}={row[i]}" for i in range(len(fields)))
        logger.info(message)

    cursor.close()
    db.close()

if __name__ == "__main__":
    main()

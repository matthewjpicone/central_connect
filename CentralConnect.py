# -*- coding: utf-8 -*-
"""
CentralConnect Module: Enabling Unified Access to Credentials.

The `CentralConnect` module serves as the heart of the DataMiner package, providing a seamless
interface for managing credentials and database connections. With robust functionalities for
handling servers, encrypting and decrypting credentials, querying databases, and more,
CentralConnect ensures that your cluster infrastructure can access a unified set of credentials
securely and efficiently.

Whether it's pinging hosts, managing network information, or interacting with PostgreSQL using
the psycopg2 driver, CentralConnect has it all covered. The module's design facilitates both GUI
and CLI interfaces, making it adaptable for various use cases.

Example
-------
You can interact with the CentralConnect module programmatically through its classes and methods:

    server = Server()
    available_hosts = server.ping_hosts()
    credentials = Credential('my_database')
    decrypted_credential = credentials.get_credential()

Notes ----- Keep your encryption secret and database password secure, as losing them will
prevent access to encrypted credentials.

Author : matthewpicone
Date   : 1/8/2023
"""

import json
import icmplib
import keyring
import psycopg2
from cryptography.fernet import Fernet
import os
from icmplib import ping, multiping
from keyring.errors import PasswordSetError

default_servers = ['127.0.0.1']
def clear_terminal():
    """
    Clears the terminal screen.

    Usage:
        clear_terminal()
    """
    os.environ['TERM'] = 'xterm-256color'
    os.system('cls' if os.name == 'nt' else 'echo -e \033c')


class Server:
    """
    A class used to represent a Server and manage network hosts.

    Attributes
    ----------
    _hosts : list
        Server hostnames for the class to try and connect to.
    _slaves : list
        Slave hostnames for the server to utilise in a cluster configuration.
    """

    def __init__(self, hosts=None, slaves=None):
        """
        Constructs a list of default known hosts and slaves.

        Parameters
        ----------
        hosts : list, optional
            Hostnames for the class to try and connect to.
        slaves : list, optional
            Slave hostnames for additional connectivity options.
        """
        self._hosts, self._slaves = None, None
        self._initialize_list('_hosts', hosts, ['127.0.0.1'])
        self._initialize_list('_slaves', slaves, ['127.0.0.1'])

    def _initialize_list(self, attr_name, attr_value, default_value):
        """
        Helper method to initialize host or slave lists.

        Parameters
        ----------
        attr_name : str
            Attribute name to be initialized.
        attr_value : list
            Value for the attribute.
        default_value : list
            Default value for the attribute.
        """
        if not attr_value:
            setattr(self, attr_name, default_value)
        else:
            try:
                setattr(self, attr_name, list(attr_value))
            except ValueError:
                raise ValueError(f"{attr_name} must be passed in as a list.")

    def ping_hosts(self):
        """Pings multiple hosts and returns their status."""
        return multiping(self._hosts, count=3, privileged=False)

    def ping_slaves(self):
        """Pings multiple slave hosts and returns their status."""
        return multiping(self._slaves, count=3, privileged=False)

    @staticmethod
    def host_is_available(host):
        """
        Checks whether a given host is available and returns True if alive.

        Parameters
        ----------
        host : str or icmplib.Host
            The host to check for availability.

        Returns
        -------
        bool
            True if the host is alive, False otherwise.
        """
        return ping(host, count=1, privileged=False).is_alive if isinstance(host,
                                                                            str) else host.is_alive

    def get_host(self):
        """
        Finds and returns an available host from the list of hosts.

        Returns
        -------
        list
            List of available hosts.
        """
        return self._hosts

    def get_slave(self):
        """
        Finds and returns an available host from the list of hosts.

        Returns
        -------
        list
            List of available hosts.
        """
        return self._slaves

    @staticmethod
    def host_network_info(host) -> dict:
        """
        Retrieves and returns network information for a given host.

        Parameters
        ----------
        host : str or icmplib.Host
            The host to retrieve network information for.

        Returns
        -------
        dict
            Dictionary containing network information such as address, RTTs, etc.
        """
        host_obj = ping(host, count=1, privileged=False) if isinstance(host, str) else host
        return {
                'address': host_obj.address,
                'min_rtt': host_obj.min_rtt,
                'avg_rtt': host_obj.avg_rtt,
                'max_rtt': host_obj.max_rtt,
                'rtts': host_obj.rtts,
                'packets_sent': host_obj.packets_sent,
                'packets_received': host_obj.packets_received,
                'packet_loss': host_obj.packet_loss,
                'jitter': host_obj.jitter,
                'is_alive': host_obj.is_alive
        }


class Credential:
    def __init__(self, credential_name=None):
        """
        Constructor for the Credential class, initializes properties and checks master key.

        Args:
            credential_name (str): Name of the credential to manage.
        """
        self._db_name = 'credential'
        self.db_user = 'credential_manager'
        self.secret_name = 'credential_secret'
        self.secret_user = 'credential_secret'

        if credential_name:
            self._name = credential_name
            self._result = None
            self._isEncrypted = None
            self._db_conn = None
            self._db_port = 5432
            self._check_master_key()  # Check if master key is present

    def _check_master_key(self):
        """
        Checks if both the credential database password and encryption secret exist in the keyring.
        If either is missing, an appropriate exception is raised, which should be handled by the
        application (either in CLI or GUI).

        Raises
        ------
        MissingPasswordException
            If the credential database password is missing in the keyring. The application must
            handle this exception and prompt the user to add a password.
        MissingSecretException
            If the encryption secret is missing in the keyring. The application must handle this
            exception and prompt the user to add a secret.
        """
        # print(keyring.get_password(self._db_name, self.db_user))
        # print(keyring.get_password(self.secret_name, self.secret_user))
        if keyring.get_password(self._db_name, self.db_user) is None:
            raise MissingPasswordException("Handle in CLI or GUI: Add a password")

        if keyring.get_password(self.secret_name, self.secret_user) is None:
            raise MissingSecretException("Handle in CLI or GUI: Add a secret")

    def reset_db_pw(self, password: str):
        """
        Resets the database password by setting a new password in the keyring.

        This method sets a new password associated with the database in the keyring, replacing
        the previous one. If the keyring encounters an issue while setting the password, a
        CentralConnectException is raised.

        Parameters
        ----------
        password : str
            The new password to be set in the keyring for the database.

        Raises
        ------
        PasswordSetError
            If the keyring encounters an error while setting the password.
        CentralConnectException
            If the keyring couldn't set the password, encapsulating the original PasswordSetError.
        """
        try:
            keyring.set_password(self._db_name, self.db_user, password)
        except PasswordSetError as e:
            raise CentralConnectException(f"Keyring couldn't set the Password {e}")
        self._check_master_key()

    def reset_secret(self, secret=None) -> str:
        """
        Resets or generates a new encryption secret in the keyring.

        This method sets a new encryption secret associated with the credentials in the keyring.
        If a new secret is provided, it will be set; otherwise, a new secret will be generated.
        If the keyring encounters an issue while setting the provided secret, a
        CentralConnectException is raised.

        Parameters
        ----------
        secret : str, optional
            The new secret to be set in the keyring for the credentials. If not provided,
            a new secret will be generated. Defaults to None.

        Returns
        -------
        str
            The new secret that has been set in the keyring.

        Raises
        ------
        PasswordSetError
            If the keyring encounters an error while setting the provided secret.
        CentralConnectException
            If the keyring couldn't set the secret, encapsulating the original PasswordSetError.
        """
        if secret:
            try:
                keyring.set_password(self.secret_name, self.secret_user, secret)
            except PasswordSetError as e:
                raise CentralConnectException(f"Keyring couldn't set the Secret {e}")
        else:
            secret = str(Fernet.generate_key())
            secret = secret[2:-1]
            keyring.set_password(self.secret_name, self.secret_user, secret)
        self._check_master_key()
        return secret

    def _decrypt(self, encrypted_data):

        """
        Private method to decrypt a given credential using Fernet.

        Args:
            encrypted_data (str): Encrypted credential.

        Returns:
            dict: Decrypted credential as a dictionary.
        """
        fernet = Fernet(keyring.get_password(self.secret_name, self.secret_user))
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        return decrypted_data

    def _encrypt(self, credential):
        """
        Private method to encrypt a given credential using Fernet.

        Args:
            credential (dict): Credential as a dictionary.

        Returns:
            bytes: Encrypted credential.
        """
        fernet = Fernet(keyring.get_password(self.secret_name, self.secret_user))
        credential_json = json.dumps(credential)
        return fernet.encrypt(credential_json.encode())

    def _query_db(self, query: str, params: tuple, return_data: bool, row_count=False):
        """
        Private method to query the database, iterates through available hosts until success.

        Notes: This database connection is designed to have a short life so teardown and build
        times aren't a concern here. Below is a dedicated database extension class for the workers
        to use.

        Args:
            query (str): SQL query string.
            params (tuple): Parameters for the SQL query.
            return_data (bool): Flag to return data from the query.
            row_count (bool, optional): Flag to return the number of affected rows. Defaults to
            False.

        Returns:
            result: Result of the query if return_data is True.
            int: Number of affected rows if row_count is True.
        """
        server = Server(hosts=default_servers)
        for host in server.get_host():
            try:
                # Connect to the database
                self._db_conn = psycopg2.connect(
                        dbname=self._db_name,
                        user=self.db_user,
                        port=self._db_port,
                        host=host,
                        password=keyring.get_password(self._db_name, self.db_user)
                )
                # Execute the query
                with self._db_conn.cursor() as cursor:
                    cursor.execute(query, params)
                    if return_data:
                        return cursor.fetchall()
                    else:
                        self._db_conn.commit()
                        if row_count:
                            return cursor.rowcount
                        else:
                            break
            except psycopg2.OperationalError as e:
                if "password authentication failed" in str(e):
                    raise AuthException("Password not configured correctly")
                else:
                    pass

        else:
            # raise ServerUnavailableException("Check network and host are configured")
            pass

    def close_db(self):
        self._db_conn.close()

    def get_credential_names(self):
        return self._query_db("""SELECT name FROM credential;""", (None,), True)

    def delete_credential(self):
        return self._query_db("""DELETE FROM public.credential WHERE name 
                                LIKE %s ESCAPE '#'""", (self._name,), False)

    # noinspection PyTypeChecker
    def get_credential(self):
        """
        Fetch and return a decrypted credential from the database.

        Returns:
            dict: Decrypted credential as a dictionary.
        """
        # Query the DB and handle the result
        result = self._query_db("""SELECT data, is_encrypted FROM credential
                    WHERE name = %s;""", (self._name,), True)
        for credential, is_encrypted in result:
            if not is_encrypted:
                self.set_credential(result, False)
                result = self._query_db("""SELECT data, is_encrypted FROM credential
                    WHERE name = %s;""", (self._name,), True)
        decrypted_data = self._decrypt(result[0][0].tobytes())
        return json.loads(decrypted_data)

    def set_credential(self, data, is_encrypted):
        """
        Set or update a credential in the database, encrypting if needed.

        Tries to update an existing record, inserts a new one if no match.

        Args:
            data (dict): Credential data as a dictionary.
            is_encrypted (bool): Flag to indicate if the data is already encrypted.
        """
        # If not encrypted, encrypt the data first
        if not is_encrypted:
            data = self._encrypt(data)  # Assuming data is already a valid JSON object
        # Update or insert the credential record in the database
        rows_updated = self._query_db("""UPDATE credential SET data = %s,
                                is_encrypted = %s
                                WHERE name = %s;""", (data, True, self._name,), False, True)
        # If no record was updated, insert a new one
        if not rows_updated:
            self._query_db("""INSERT INTO credential (data, is_encrypted, name)
                                VALUES(%s, %s, %s);""", (data, True, self._name,), False)


class PostgreSQL:
    """
    A class that facilitates interactions between the miner and the psycopg2 driver.

    Attributes
    ----------
    _conn : psycopg2 connection object
        Connection to the PostgreSQL database.
    _cursor : psycopg2 cursor object
        Cursor for executing SQL commands.
    """

    def __init__(self, db_name):
        """
        Establishes a database connection using psycopg2.
        The credentials for the connection are managed by the
        CredentialManager.

        Parameters
        ----------
        db_name : str
            The ID of the database connection in the CredentialManager.

        Raises
        ------
        ConnectionHandlerException
            If there's an issue establishing a connection with the database.
        """
        c = Credential(db_name)
        credentials = c.get_credential()  # Retrieve the credentials
        server = Server(credentials['host'])  # Get a list of available hosts
        for host in server.get_host():
            try:
                connection_properties = credentials['connection_properties']
                connection_properties['host'] = host
                # Connect to the database
                self._conn = psycopg2.connect(**connection_properties)
                self._cursor = self._conn.cursor()
                break  # When we have a connection break
            except psycopg2.OperationalError:
                pass  # Attempt all servers in list
        else:
            raise ServerUnavailableException("No Server/s Found")
        c.close_db()

    def commit(self):
        """
        Commits any pending transactions to the database.

        Raises
        ------
        ConnectionHandlerException
            If a database error occurs during the commit.
        """
        try:
            self._conn.commit()
        except (psycopg2.DatabaseError, psycopg2.InterfaceError) as e:
            raise OperationException(
                    "Failed to commit transactions to the database. "
                    "Please check the database status and your transactions. "
                    f"Original error: {e}")

    def rollback(self):
        """
        Rolls back any pending transactions in the database.

        Raises
        ------
        ConnectionHandlerException
            If a database error occurs during the rollback.
        """
        try:
            self._conn.rollback()
        except (psycopg2.DatabaseError, psycopg2.InterfaceError) as e:
            raise OperationException(
                    "Failed to roll back transactions in the database. "
                    "Please check the database status and your transactions. "
                    f"Original error: {e}")

    def close_db(self):
        """
        Closes the cursor and the database connection.

        Raises
        ------
        ConnectionHandlerException
            If a database error occurs during the closing of the connection.
        """
        try:
            self._cursor.close()
            self._conn.close()
        except (psycopg2.DatabaseError, psycopg2.InterfaceError) as e:
            raise OperationException(
                    "Failed to close the database connection. "
                    "Please ensure there are no pending transactions. "
                    f"Original error: {e}")

    def get_data(self, command, params=None):
        """
        Retrieves data from the DB.

        Parameters
        ----------
        command : str
            The SQL command to execute.
        params : tuple, optional
            The parameters for the SQL command.

        Raises
        ------
        ConnectionHandlerException
            If a database error occurs during the execution of the command.
        """
        try:
            self._cursor.execute(command, params)
            return self._cursor.fetchall()
        except (psycopg2.DatabaseError, psycopg2.InterfaceError):
            raise QueryException("Nothing to return")

    def insert_clean_dataset(self, query, params, should_commit=True):
        """
        Inserts a clean dataset into the database.

        This method is faster than the insert_dataset method below however does not come with the
        risk that if one query fails the entire transaction is cancelled.

        Parameters
        ----------
        query : str
            SQL query string for the insertion.
        params : list[tuple]
            Parameters for the SQL query.

        Raises
        ------
        InsertionException
            If the insertion fails.
        """
        try:
            self._cursor.executemany(query, params)
            if should_commit:
                self.commit()
        except (psycopg2.DatabaseError, psycopg2.InterfaceError) as e:
            self.rollback()
            raise InsertionException(f"Query Failed, rollback complete : {e}")

    def insert_one_fallback(self, query, params):
        """
        Inserts a clean dataset into the database.

        This method is faster than the insert_dataset method below however does not come with the
        risk that if one query fails the entire transaction is cancelled.

        Parameters
        ----------
        query : str
            SQL query string for the insertion.
        params : tuple
            Parameters for the SQL query.

        Raises
        ------
        InsertionException
            If the insertion fails.
        """
        try:
            self._cursor.execute(query, params)
            self.commit()
        except (psycopg2.DatabaseError, psycopg2.InterfaceError) as e:
            self.rollback()
            raise InsertionException(f"Query Failed, rollback complete : {e}")

    def insert_dataset(self, query: list):
        """
        Executes a list of SQL queries given as tuples containing the SQL
        statement and its corresponding parameters.

        Parameters
        ----------
        query : list
            A list of tuples, each containing an SQL command as a string (first element),
            and its corresponding parameters as a list, tuple, or dictionary (second element).

        Raises
        ------
        QueryParameterTypeError, ConnectionHandlerException, QueryException
        """

        try:
            for sql, params in query:
                if params is not None:
                    if isinstance(params, (list, tuple, dict)):
                        if isinstance(sql, list):
                            for command in sql:
                                self._cursor.execute(command, params)
                        else:
                            self._cursor.execute(sql, params)
                    else:
                        raise InvalidParameterException(
                                'Invalid parameter type. Please ensure that the parameters '
                                'passed to each query in the run_query method are of type '
                                'list, tuple, or dictionary. All queries sent have been '
                                'rolled back.')
                else:
                    self._cursor.execute(sql)
        except psycopg2.Error as e:
            self.rollback()
            raise InsertionException(
                    'A database error occurred while executing your query. Please check the '
                    'connection and '
                    'the syntax of your query. All changes made in this transaction have been '
                    'rolled back. '
                    f'Original Error: {e}')
        except Exception as e:
            self.rollback()
            raise QueryException(
                    'An unexpected error occurred while executing your query. This error is '
                    'neither a type error '
                    'nor a database issue. Ensure the spelling of your parameter keyval matches '
                    f'the header of the input file. Original Error: {e}')

        finally:
            self.commit()


class CentralConnectException(Exception):
    """
    Base exception class for CentralConnect. All custom exceptions in CentralConnect
    should inherit from this class. This helps in providing a unified way of handling
    errors that are specific to CentralConnect.
    """


class InsertionException(CentralConnectException):
    """
    Exception raised when a database insertion operation fails. This can include
    issues related to constraints, duplicates, or any other conditions that prevent
    the successful insertion of data into the database.
    """


class InvalidQueryException(CentralConnectException):
    """
    Exception raised when a SELECT statement or other query fails. This can be due
    to syntax errors, referencing non-existent columns or tables, or other issues
    related to the formation or execution of a query.
    """


class InvalidParameterException(CentralConnectException):
    """
    Exception raised when an invalid or inappropriate parameter type is passed to a
    method. This can include incorrect data types, values out of bounds, or other
    conditions that make the parameter unacceptable.
    """


class QueryException(CentralConnectException):
    """
    General exception raised for errors related to the formation or execution of a
    query. This could encompass a wide range of issues, including but not limited to,
    syntax errors, logical errors, or runtime execution problems.
    """


class OperationException(CentralConnectException):
    """
    Exception raised when a database connection operation fails. This includes issues
    related to connecting, disconnecting, committing, rolling back, or any other
    operation that involves interacting with the database.
    """


class AuthException(CentralConnectException):
    """
    Exception raised when a database connection operation fails due to bad password.
    The user should call the Credential().reset_db_pw() to rectify the password missmatch.
    """


class ServerUnavailableException(CentralConnectException):
    """
    Exception raised when a database connection operation fails due to either network availability
    or a bad hostname provided.
    """


class MissingPasswordException(CentralConnectException):
    """
    Exception raised when there is no password available for the Credential DB.
    To be handled by calling application.
    """


class MissingSecretException(CentralConnectException):
    """
    Exception raised when there is no secret available for the Credential DB.
    To be handled by calling application.
    """


def main():
    pass


if __name__ == '__main__':
    main()

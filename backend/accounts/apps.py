import os
from django.apps import AppConfig
from django.db import connection, OperationalError, IntegrityError
from django.conf import settings

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        if os.environ.get('RUN_MAIN', None) == 'true':  
            sql_dir = os.path.join(settings.BASE_DIR, "MYSQL")  
            if os.path.exists(sql_dir) and os.path.isdir(sql_dir):
                sql_files = ["country.sql", "state.sql", "city.sql"]
                sql_files = [os.path.join(sql_dir, f) for f in sql_files if os.path.exists(os.path.join(sql_dir, f))]
                for sql_file_path in sql_files:
                    try:
                        with open(sql_file_path, 'r') as file:
                            sql_commands = file.read()

                        if sql_commands.strip():
                            with connection.cursor() as cursor:
                                for command in sql_commands.split(";"):
                                    clean_command = command.strip()
                                    if clean_command:
                                        if "INSERT INTO" in clean_command.upper():
                                            # Modiefied 
                                            modified_command = clean_command.replace("INSERT INTO", "INSERT IGNORE INTO")
                                            cursor.execute(modified_command)
                                        else:
                                            cursor.execute(clean_command)

                                print(f"Successfully executed: {sql_file_path}")
                            table_name = self.get_table_name(sql_file_path)
                            if table_name:
                                self.print_new_entries(table_name)

                    except IntegrityError as e:  
                        print(f"IntegrityError in {sql_file_path}: {e}")
                    except OperationalError as e:  
                        print(f"OperationalError in {sql_file_path}: {e}")
                    except Exception as e:
                        print(f"Error executing {sql_file_path}: {e}")

            else:
                print("SQL directory not found or empty!")

    def get_table_name(self, sql_file_path):
        file_name = os.path.basename(sql_file_path)
        mapping = {
            "country.sql": "accounts_country",
            "state.sql": "accounts_state",
            "city.sql": "accounts_city",
        }
        return mapping.get(file_name)

    def print_new_entries(self, table_name):
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT * FROM `{table_name}` ORDER BY created_at DESC LIMIT 10;")
                new_entries = cursor.fetchall()
                print(f"\nLast inserted entries in `{table_name}`:")
                for entry in new_entries:
                    print(entry)

        except Exception as e:
            print(f"Could not fetch new entries from `{table_name}`: {e}")

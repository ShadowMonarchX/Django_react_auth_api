from django.db import connection
import os

def load_sql_from_file(file_path):
    
    with open(file_path, "r", encoding="utf-8") as file:
        sql_commands = file.read().split(";")
    return [cmd.strip() for cmd in sql_commands if cmd.strip()]

def run_sql_scripts(apps, schema_editor):
    
    sql_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "MYSQL")

    if os.path.exists(sql_dir) and os.path.isdir(sql_dir):
        sql_files = ["country.sql", "state.sql", "city.sql"]
        for sql_file in sql_files:
            file_path = os.path.join(sql_dir, sql_file)
            if os.path.exists(file_path):
                sql_commands = load_sql_from_file(file_path)
                with connection.cursor() as cursor:
                    for command in sql_commands:
                        try:
                            if "INSERT INTO" in command.upper():
                                modified_command = command.replace("INSERT INTO", "INSERT IGNORE INTO")
                                cursor.execute(modified_command)
                            else:
                                cursor.execute(command)
                        except Exception as e:
                            print(f"Error executing {sql_file}: {e}")
                print(f"Successfully executed {sql_file}")
    else:
        print("SQL directory not found or empty!")

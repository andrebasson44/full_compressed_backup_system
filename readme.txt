PROGRAM:  Full Backup System
AUTHOR: Andre Basson

DESCRIPTION: 
Typical FULL (gzip archiving) backup script, which syncs data - files and directories listed in ./toBackup.txt - from a location
on the local host to another location on the local host, or between a location on the local host to another on a remote host.  
	
	              *** CURRENTLY NO DATA CAN BE BACKED UP (PULLED) FROM A REMOTE HOST ***

INSTRUCTIONS
1. create a directory to house all files, eg. ~/full-backup
2. copy all files into directory in (1)
3. list all the directories (or files) to backup in ./toBackup.txt (full paths only)
4. configure backup parameters in ./full-backup.conf (follow comments for guidance)
5. optional: add files/directories to exclude from backup in ./backup_exclude_list.txt
6. optional: automate backups with crontab
7. ensure all requirements (see below) has been fulfilled.
8. execute backup by running the *.sh file either manually or as crontab scheduled task

REQUIREMENTS:  System software: 
*OPTIONAL: A local, send-only SMTP server (e.g. Postfix) - no dedicated email or 3rd party SMTP server is required Postfix configured to forward all 
system-generated email sent to root, to skyqode@gmail.com (see documentation or https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-postfix-as-a-send-only-smtp-server-on-ubuntu-14-04) b) Rsync c) SSH - with hosts configured for RSA public/private key pair

IMPORTANT:		
  a) The script should be run with sudo/admin privaleges, so as to ensure proper execution at all times.
  b) As part of the incremental backup schema, the following file-directory structure is critical:
	1. /path/to/script/backup-info
		- a 'backup-info' directory at the same path as where this script resides, with rwx access to sudo user
			> this directory preserves the means by which important log files are stored and processed.
			> this directory is created automatically, and it (or its content) my be deleted when the program is not running.


	2. /path/to/script/files
		- a 'files' directory at the same path as where this script resides, with rwx access to sudo user
			> this directory contains programs/scripts critical to the function of the backup script.
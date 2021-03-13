# hide
File AES encryption service written in pure Rust.

Helps you keep your data secure, private and hidden.
Encrypts files via the AES symmetric cipher.
Secured with two passwords.

Commands:
 - enfile <file> – encrypt exact file
 - en <arguments> – encrypt current dir with arguments
 - defile <file> – decrypt exact file
 - de <arguments> – decrypt current dir with arguments
 - revoke – delete saved password data
 - help – display this help
 - cd – change directory to default
 - cd <dir> – change directory to the one specified
 - ld – list current directory
 - st – display propeerties of current directory
 - exit

Arguments of commands de/en:
 - all – reset filter queue
 - none/only – ignore all files (but why?)
 - as – apply to all sizes of files
 - at – apply to all file types
 - f – apply to all files in folders
 - -f – ignore folders
 - s – apply to small files
 - -s – ignore small files
 - m – apply to medium sized files
 - -m – ignore all medium sized files
 - l – apply to large files
 - -l – ignore all large files
 - p – apply to pictures
 - -p – ignore all pictures
 - v – apply to videos
 - -v – ignore all videos
 - a – apply to audio files
 - -a – ignore all audio files
 - t – apply to text files
 - -t – ignore all text files
 - N, where N is an index of file in selected folder – apply to N file in selected directory
 - X..Y, where N is an index of file in selected directory – apply to all files from X to Y (including) in selected directory
 - 'NAME', where NAME is a file name (w/o extension)

Note about smart filters: file names and intervals have the biggest privelege

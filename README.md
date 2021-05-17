# hide
File AES encryption service written in pure Rust.

Helps you keep your data secure, private and hidden.
Encrypts files via the AES symmetric cipher.
Secured with two passwords.

#### Commands:
* enfile <path> – encrypt exact file
* en <arguments> – encrypt current dir with arguments
* defile <path> – decrypt exact file
* de <arguments> – decrypt current dir with arguments

#### Arguments of commands de/en:
* all – reset filter queue
* none/only – filter all files
* as – apply to all sizes of files
* -as – filter all sizes of files
* at – apply to all file types
* -at – filter all file types
* f – apply to folders
* -f – filter folders
* s – apply to small files
* -s – filter small files
* m – apply to medium sized files
* -m – filter all medium sized files
* l – apply to large files
* -l – filter large files
* p – apply to pictures
* -p – filter pictures
* v – apply to videos
* -v – filter videos
* a – apply to audio files
* -a – filter audio files
* t – apply to text files
* -t – filter text files
* N, where N is an index of file in selected folder – apply to N file in selected directory
* X..Y, where X and Y are indexes – apply to all files from X to Y (inclusive) in selected directory
* 'NAME', where NAME is a file name (w/o extension) – apply to exact file
* revoke – delete saved password data
* help – display this help
* cd – change directory to default
* cd <dir> – change directory to the one specified
* ld – list current directory
* st – display properties of current directory

#### Example usage: 
 * `en only p as 1..6 9` – encypt only pictures of all sizes in interval 1 to 6 and 9th separately
 * `de all` – decrypt every file (w/o recursion)
 * `en all f -l` – encrypt every file with folders inside folders, but ignore large files
 
Note about smart filters: file names and intervals have the biggest privelege";

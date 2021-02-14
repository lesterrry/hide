# hide
File AES encryption service written in pure Rust.

Helps you keep your data secure, private and hidden.
Encrypts files via the AES symmetric cipher.
Secured with two passwords.

Commands:
 - en – encrypt current directory
 - en f <file> – encrypt exact file
 - en <arguments> – encrypt with smart filters
 - de – decrypt current directory
 - de f <file> – decrypt exact file
 - de <arguments> – decrypt with smart filters
 - revoke – delete saved password data
 - help – display this help
 - cd – change directory to default
 - cd <dir> – change directory to the one specified
 - ld – list current directory
 - st – display propeerties of current directory

Arguments of commands de/en:
 - all/only – reset filter queue
 - none – filter all files
 - sizes – apply to all sizes of files
 - -sizes – filter all sizes of files
 - types – apply to all file types
 - -types – filter all file types
 - s – apply to small files
 - -s – filter small files
 - m – apply to medium sized files
 - -m – filter all medium sized files
 - l – apply to large files
 - -l – filter large files
 - p – apply to pictures
 - -p – filter pictures
 - v – apply to videos
 - -v – filter videos
 - a – apply to audio files
 - -a – filter audio files
 - t – apply to text files
 - -t – filter text files
 - N, where N is an index of file in selected folder – apply to N file in selected directory
 - X..Y, where N is an index of file in selected directory – apply to all files from X to Y (including) in selected directory

Note about smart filters: one should build queue from the least important filter, to the most. The last filter will always apply the last.
For example, queue `only m l p -l` will at first reset filter (only), thus passing every file, then selecting medium sized files (m), large files (l) and pictures (p), and deselecting large files at the end (-l). '-l' filter stays after the 'l', thus disabling it.

Another example: queue `p a v sizes -b all` makes no sense, as 'all' filter as the end will disable all previous, and every file will be passed.
So, if we remove it, the queue will look like this: `p a v sizes -b`, selecting all pictures (p), audios (a) and videos (v), and all sizes of files except big ones (sizes -b). We can make it even better, by passing `types -t sizes -b`, selecting all file types except text ones, and all sizes except big ones.

# Short demo of nudi-view on a finished run folder. Run from tui/: vhs demo.tape
# RUN defaults to a fixture; set it to a recorded run folder to film a real run.
# Writes demo.mp4 and demo.gif into the current directory.

Output demo.mp4
Output demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 720
Set Padding 24
Set Framerate 24
Set TypingSpeed 45ms
Set Theme "GitHub Dark"

Hide
Type `mkdir -p $TMPDIR/nudi-demo && go build -o $TMPDIR/nudi-demo/nudi-view . && export PATH=$TMPDIR/nudi-demo:$PATH PS1='$ ' RUN=${RUN:-testdata/full} && clear`
Enter
Sleep 8s
Show

Type "nudi-view $RUN"
Sleep 600ms
Enter
Sleep 6s
Left
Sleep 2500ms
Left
Sleep 2500ms
Left
Sleep 2500ms
Left
Sleep 2500ms
Enter
Sleep 3s
Tab
Sleep 3s
Tab
Right
Sleep 2500ms
Escape
Sleep 1s
Type "q"
Sleep 1s

Type "nudi-view $RUN 1 | head -20"
Sleep 400ms
Enter
Sleep 4s

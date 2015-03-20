#! /bin/bash
# Jonathan 2015

#start server and capture out to file - backgrounding it
python -u server.py > output.txt&

#wait a few seconds
sleep 3
#use awk to print the first line of output file and use sed to only select the port
#works the the 5 digit ports mac is always assigning the server
output=`awk  'NR==1{print $4}' output.txt | sed 's/.\{2\}$//'`

echo "Setting new Port in client"
echo $output

# use perl to relace the 16th line of the client code with the new port
perl -i -pe "s/.*/PORT=$output/ if $.==16" client.py

# store operating directory and use apple script to open new terminal tabs 
# and execectue the GUI chat program in each
pwd=`pwd`
osascript -e "tell application \"Terminal\"" \
    -e "tell application \"System Events\" to keystroke \"t\" using {command down}" \
    -e "do script \"cd $pwd; ./chatClientGUI.py \" in front window" \
    -e "end tell"
    > /dev/null;


osascript -e "tell application \"Terminal\"" \
    -e "tell application \"System Events\" to keystroke \"t\" using {command down}" \
    -e "do script \"cd $pwd; ./chatClientGUI.py \" in front window" \
    -e "end tell"
    > /dev/null;

osascript -e "tell application \"Terminal\"" \
    -e "tell application \"System Events\" to keystroke \"t\" using {command down}" \
    -e "do script \"cd $pwd; ./chatClientGUI.py \" in front window" \
    -e "end tell"
    > /dev/null;


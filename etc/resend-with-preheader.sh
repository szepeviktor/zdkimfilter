#! /bin/sh

opt_a=""
opt_s=""

sendit()
{
	blank=$(egrep -n '^$' "$1" | egrep -v '^1:' | sed 's/\([0-9]*\):.*/\1/' | head -1)
	if [ $blank -gt 1 ]; then
		first=$(echo $blank + 1 | bc)
		last=$(echo $blank - 1 | bc)
		sender=$(head -1 $1)
		recipients=$(head -$last $1| tail -n +2)
		if [ -z "$opt_s" ]; then
			printf 'file: %s\n' "$1"
			printf 'command and args: sendmail -f %s %s %s\n' \
				$(test -z "$sender" && echo '""' || echo $sender) \
				"$opt_a" "$recipients"
		fi
		tail -n +$first $1 | sendmail -f "$sender" $opt_a $recipients
		rtc=$?
		if [ -z "$opt_s" ]; then
			echo "rtc = $rtc"
		fi
	fi
}

while [ $# -gt 0 ]; do
	arg="$1"
	shift
	case $arg in
	-a) opt_a="$1"; shift;;
	-s) opt_s="s";;
	-*) echo "invalid option $arg";;
	*) set "$arg" "$@"; break;;
	esac
done

for arg; do
	if [ -f "$arg" ]; then
		sendit "$arg"
	else
		echo "$arg is not a file"
	fi
done

		

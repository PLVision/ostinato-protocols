#!/bin/bash

arg1=$1
echo -e 'check environment: '
echo -ne '\tqmake: '
if ! dpkg -l | grep qmake &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tprotobuf: '
if ! dpkg -l | grep protobuf-compiler &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tpip: '
if ! dpkg -l | grep pip &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tlibpcre-ocaml-dev: '
if ! dpkg -l | grep libpcre-ocaml-dev &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tlibqt4-dev: '
if ! dpkg -l | grep libqt4-dev &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tlibqt4-core: '
if ! dpkg -l | grep libqt4-core &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tlibqt4-qt3support: '
if ! dpkg -l | grep libqt4-qt3support &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi
echo -ne '\tpython-ostinato: '
if ! pip search python-ostinato | grep INSTALLED: &> /dev/null; then
	echo 'no'
	exit 1
else
	echo 'yes'
fi

echo "you select protocol: $arg1"
echo -n "find protocol branch: "
if ! git branch -a | grep "release-"$arg1 &> /dev/null; then
	echo -e "no\n you can change next branches:"
	git branch
	exit 1
else
	echo "yes"
	git checkout "release-"$arg1 &> /dev/null
fi

echo -n "pull new changes: "
if ! git pull  2>&1| grep 'up-to-date' &> /dev/null; then
	echo -e "no\n git pull error"
	read -r -p "${1:-continue without a pull? [y/N]} " response
	case $response in
		[yY][eE][sS]|[yY]) 
			;;
		*)
			exit 1
			;;
		esac
else
	echo "yes"
fi

echo -n "run qmake: "
if qmake 2>&1| grep 'error' &> /dev/null; then
	echo -e "no"
	exit 1
else
	echo "yes"
fi

echo -n "run make: "
if make 2>&1| grep 'error'&> /dev/null; then
	echo -e "no"
	exit 1
else
	echo "yes"
fi

echo -n "run make: "
if make 2>&1| grep 'error'&> /dev/null; then
	echo -e "no"
	exit 1
else
	echo "yes"
fi
echo -n "update python-ostinato libs: "
if [ -d "/usr/local/lib/python-2.7/dist-packages/ostinato" ]; then
	sudo cp -rf binding/* /usr/local/lib/python-2.7/dist-packages/ostinato/
	echo "yes"
elif [ -d "/usr/local/lib/python2.7/dist-packages/ostinato" ]; then
	sudo cp -rf binding/* /usr/local/lib/python2.7/dist-packages/ostinato/
	echo "yes"
else
	echo "no"
	exit 1
fi


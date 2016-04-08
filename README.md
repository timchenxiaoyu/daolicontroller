Daolicontroller for daolinet
============================

DaoliController is an OpenFlow Controller which DaoliNet modifies from Ryu to suit a number of novel uses.


All of the code is freely available under the Apache 2.0 license.
Daolicontroller is fully written in Python.

Quickstart
----------

#### Install ryu that is a openflow framework

	pip install ryu

#### Install requirement package

	yum install -y python-requests python-docker-py

#### Install openflow daolicontroller

	git clone https://github.com/daolicloud/daolicontroller.git
	cd daolicontroller; python ./setup.py install

#### Run

	daolicontroller

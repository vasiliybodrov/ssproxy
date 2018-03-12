#! /bin/sh

# ##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2018 Vasiliy V. Bodrov aka Bodro, Ryazan, Russia
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ##############################################################################

export DB_HOST=${1}
export DB_PORT=${2}
export DB_USER=${3}
export DB_PASSWORD=${4}

if [ ${#} -eq 0 ]; then
    echo "Use: ${0} <HOST> <PORT> <USER> <PASSWORD>"
    echo "Example: ${0} 192.168.0.1 4880 root 123456"
    exit 0
fi

#
# mysql> create database sbtest;
#

sysbench --num-threads=10 \
         --test=oltp \
         --mysql-host=${DB_HOST} \
         --mysql-port=${DB_PORT} \
         --mysql-user=${DB_USER} \
         --mysql-password=${DB_PASSWORD} \
         --oltp-table-size=500000 \
         --db-driver=mysql \
         --mysql-table-engine=myisam \
         prepare

sysbench --num-threads=10 \
         --test=oltp \
         --mysql-host=${DB_HOST} \
         --mysql-port=${DB_PORT} \
         --mysql-user=${DB_USER} \
         --mysql-password=${DB_PASSWORD} \
         --oltp-table-size=500000 \
         --db-driver=mysql \
         --mysql-table-engine=myisam \
         run

sysbench --test=oltp \
         --mysql-host=${DB_HOST} \
         --mysql-port=${DB_PORT} \
         --mysql-user=${DB_USER} \
         --mysql-password=${DB_PASSWORD} \
         --db-driver=mysql \
         cleanup

# ##############################################################################
# End of file
# ##############################################################################

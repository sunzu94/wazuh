#!/usr/bin/env python

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from concurrent.futures import ProcessPoolExecutor

master_pool = ProcessPoolExecutor(max_workers=2)
master_pool.map(lambda: None, range(master_pool._max_workers))

import argparse
import asyncio
import logging
import os
import sys
from signal import signal, Signals, SIGTERM, SIG_DFL

from psutil import Process


#
# Aux functions
#

def set_logging(foreground_mode=False, debug_mode=0):
    cluster_logger = cluster_utils.ClusterLogger(foreground_mode=foreground_mode, log_path='logs/cluster.log',
                                                 debug_level=debug_mode,
                                                 tag='{asctime} {levelname}: [{tag}] [{subtag}] {message}')
    cluster_logger.setup_logger()
    return cluster_logger


def print_version():
    from wazuh.core.cluster import __version__, __author__, __wazuh_name__, __licence__
    print("\n{} {} - {}\n\n{}".format(__wazuh_name__, __version__, __author__, __licence__))


def terminate_child_processes(parent_pid):
    """Stop the execution of all cluster child processes.

    Parameters
    ----------
    parent_pid : int
        Parent process ID.
    """
    for child in Process(parent_pid).children(recursive=True):
        try:
            child.kill()
        except Exception:
            pass


def exit_handler(signum, frame):
    cluster_pid = os.getpid()
    main_logger.info(f'SIGNAL [({signum})-({Signals(signum).name})] received. Exit...')

    # Terminate cluster's child processes
    terminate_child_processes(cluster_pid)

    # Remove cluster's pidfile
    pyDaemonModule.delete_pid('wazuh-clusterd', cluster_pid)

    if callable(original_sig_handler):
        original_sig_handler(signum, frame)
    elif original_sig_handler == SIG_DFL:
        # Call default handler if the original one can't be run
        signal(signum, SIG_DFL)
        os.kill(os.getpid(), signum)


def process_spawn_sleep():
    """Simple task to force the cluster pool spawn all its children."""
    return

#
# Master main
#
async def master_main(args, cluster_config, cluster_items, logger):
    from wazuh.core.cluster import master, local_server
    cluster_utils.context_tag.set('Master')
    my_server = master.Master(performance_test=args.performance_test, concurrency_test=args.concurrency_test,
                              configuration=cluster_config, enable_ssl=args.ssl, logger=logger,
                              cluster_items=cluster_items)
    my_local_server = local_server.LocalServerMaster(performance_test=args.performance_test, logger=logger,
                                                     concurrency_test=args.concurrency_test, node=my_server,
                                                     configuration=cluster_config, enable_ssl=args.ssl,
                                                     cluster_items=cluster_items)
    # Spawn pool processes if needed
    my_server.task_pool = master_pool
    # my_server.task_pool.map(cluster_utils.process_spawn_sleep, range(my_server.task_pool._max_workers))
    await asyncio.gather(my_server.start(), my_local_server.start())


#
# Worker main
#
async def worker_main(args, cluster_config, cluster_items, logger):
    from wazuh.core.cluster import worker, local_server
    cluster_utils.context_tag.set('Worker')
    while True:
        my_client = worker.Worker(configuration=cluster_config, enable_ssl=args.ssl,
                                  performance_test=args.performance_test, concurrency_test=args.concurrency_test,
                                  file=args.send_file, string=args.send_string, logger=logger,
                                  cluster_items=cluster_items)
        my_local_server = local_server.LocalServerWorker(performance_test=args.performance_test, logger=logger,
                                                         concurrency_test=args.concurrency_test, node=my_client,
                                                         configuration=cluster_config, enable_ssl=args.ssl,
                                                         cluster_items=cluster_items)
        try:
            await asyncio.gather(my_client.start(), my_local_server.start())
        except asyncio.CancelledError:
            logging.info("Connection with server has been lost. Reconnecting in 10 seconds.")
            await asyncio.sleep(cluster_items['intervals']['worker']['connection_retry'])


#
# Main
#
if __name__ == '__main__':
    import wazuh.core.cluster.cluster
    import wazuh.core.cluster.utils as cluster_utils
    from wazuh.core import pyDaemonModule, common, configuration
    from wazuh.core.utils import check_pid

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    # Dev options - Silenced in the help message.
    ####################################################################################################################
    # Performance test - value stored in args.performance_test will be used to send a request of that size in bytes to
    # all clients/to the server.
    parser.add_argument('--performance_test', type=int, dest='performance_test', help=argparse.SUPPRESS)
    # Concurrency test - value stored in args.concurrency_test will be used to send that number of requests in a row,
    # without sleeping.
    parser.add_argument('--concurrency_test', type=int, dest='concurrency_test', help=argparse.SUPPRESS)
    # Send string test - value stored in args.send_string variable will be used to send a string with that size in bytes
    # to the server. Only implemented in worker nodes.
    parser.add_argument('--string', help=argparse.SUPPRESS, type=int, dest='send_string')
    # Send file test - value stored in args.send_file variable is the path of a file to send to the server. Only
    # implemented in worker nodes.
    parser.add_argument('--file', help=argparse.SUPPRESS, type=str, dest='send_file')
    ####################################################################################################################
    parser.add_argument('--ssl', help="Enable communication over SSL", action='store_true', dest='ssl', default=False)
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", action='count',
                        dest='debug_level')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file',
                        default=common.ossec_conf)
    args = parser.parse_args()

    if args.version:
        print_version()
        sys.exit(0)

    # Set logger
    try:
        debug_mode = configuration.get_internal_options_value('wazuh_clusterd', 'debug', 2, 0) or args.debug_level
    except Exception:
        debug_mode = 0

    # set correct permissions on cluster.log file
    if os.path.exists('{0}/logs/cluster.log'.format(common.wazuh_path)):
        os.chown('{0}/logs/cluster.log'.format(common.wazuh_path), common.wazuh_uid(), common.wazuh_gid())
        os.chmod('{0}/logs/cluster.log'.format(common.wazuh_path), 0o660)

    main_logger = set_logging(foreground_mode=args.foreground, debug_mode=debug_mode)

    cluster_configuration = cluster_utils.read_config(config_file=args.config_file)
    if cluster_configuration['disabled']:
        sys.exit(0)
    cluster_items = cluster_utils.get_cluster_items()
    try:
        wazuh.core.cluster.cluster.check_cluster_config(cluster_configuration)
    except Exception as e:
        main_logger.error(e)
        sys.exit(1)

    if args.test_config:
        sys.exit(0)

    cluster_status = wazuh.core.cluster.utils.get_cluster_status()
    if cluster_status['running'] == 'yes':
        main_logger.error("Cluster is already running.")
        sys.exit(1)

    # clean
    wazuh.core.cluster.cluster.clean_up()

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()

    # Drop privileges to wazuh
    if not args.root:
        os.setgid(common.wazuh_gid())
        os.setuid(common.wazuh_uid())

    check_pid('wazuh-clusterd')
    pid = os.getpid()
    pyDaemonModule.create_pid('wazuh-clusterd', pid)
    if args.foreground:
        print(f"Starting cluster in foreground (pid: {pid})")

    original_sig_handler = signal(SIGTERM, exit_handler)

    main_function = master_main if cluster_configuration['node_type'] == 'master' else worker_main
    try:
        asyncio.run(main_function(args, cluster_configuration, cluster_items, main_logger))
    except KeyboardInterrupt:
        main_logger.info("SIGINT received. Bye!")
    except MemoryError:
        main_logger.error("Directory '/tmp' needs read, write & execution "
                          "permission for 'wazuh' user")
    except Exception as e:
        main_logger.error(f"Unhandled exception: {e}")
    finally:
        terminate_child_processes(pid)
        pyDaemonModule.delete_pid('wazuh-clusterd', pid)

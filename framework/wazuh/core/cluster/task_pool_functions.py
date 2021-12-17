# from calendar import timegm
# from collections import defaultdict
import os
from datetime import datetime
from os import stat, walk
from os.path import join, basename, isfile, relpath, getmtime, abspath, dirname
# from time import time
from typing import Dict

# from wazuh.core.cluster.utils import get_cluster_items
# from wazuh.core.cluster.cluster import unmerge_info
from wazuh.core.common import wazuh_path, wazuh_uid, wazuh_gid, cluster_integrity_mtime
from wazuh.core.exception import WazuhClusterError, WazuhInternalError, WazuhError
# from wazuh.core.utils import Timeout, safe_move, md5
# from wazuh.core.wdb import WazuhDBConnection
from logging import getLogger
import hashlib
from json import load
from operator import setitem
from functools import lru_cache


logger = getLogger('wazuh')


# @lru_cache()
def get_cluster_items():
    """Load and return the content of cluster.json file as a dict.

    Returns
    -------
    cluster_items : dict
        Dictionary with the information inside cluster.json file.
    """
    try:
        here = abspath(dirname(__file__))
        with open(join(wazuh_path, here, 'cluster.json')) as f:
            cluster_items = load(f)
        # Rebase permissions.
        list(map(lambda x: setitem(x, 'permissions', int(x['permissions'], base=0)),
                 filter(lambda x: 'permissions' in x, cluster_items['files'].values())))
        return cluster_items
    except Exception as e:
        raise WazuhError(3005, str(e))


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def walk_dir(dirname, recursive, files, excluded_files, excluded_extensions, get_cluster_item_key, get_md5=True, data={}):
    """Iterate recursively inside a directory, save the path of each found file and obtain its metadata.

    Parameters
    ----------
    dirname : str
        Directory within which to look for files.
    recursive : bool
        Whether to recursively look for files inside found directories.
    files : list
        List of files to obtain information from.
    excluded_files : list
        List of files to ignore.
    excluded_extensions : list
        List of extensions to ignore.
    get_cluster_item_key : str
        Key inside cluster.json['files'] to which each file belongs. This is useful to know what actions to take
        after sending a file from one node to another, depending on the directory the file belongs to.
    get_md5 : bool
        Whether to calculate and save the MD5 hash of the found file.

    Returns
    -------
    walk_files : dict
        Paths (keys) and metadata (values) of the requested files found inside 'dirname'.
    """
    walk_files = {}

    # Get the information collected in the previous integration process.
    previous_status = data

    full_dirname = join(wazuh_path, dirname)
    # Get list of all files and directories inside 'full_dirname'.
    try:
        for root_, _, files_ in walk(full_dirname, topdown=True):
            # Check if recursive flag is set or root is actually the initial lookup directory.
            if recursive or root_ == full_dirname:
                for file_ in files_:
                    # If file is inside 'excluded_files' or file extension is inside 'excluded_extensions', skip over.
                    if file_ in excluded_files or any([file_.endswith(ext) for ext in excluded_extensions]):
                        continue
                    try:
                        #  If 'all' files have been requested or entry is in the specified files list.
                        if files == ['all'] or file_ in files:
                            relative_file_path = join(relpath(root_, wazuh_path), file_)
                            abs_file_path = join(root_, file_)
                            file_mod_time = getmtime(abs_file_path)
                            try:
                                if file_mod_time == previous_status[relative_file_path]['mod_time']:
                                    # The current file has not changed its mtime since the last integrity process.
                                    walk_files[relative_file_path] = previous_status[relative_file_path]
                                    continue
                            except KeyError:
                                pass
                            # Create dict with metadata for the current file.
                            file_metadata = {"mod_time": file_mod_time, 'cluster_item_key': get_cluster_item_key}
                            if '.merged' in file_:
                                file_metadata['merged'] = True
                                file_metadata['merge_type'] = 'agent-groups'
                                file_metadata['merge_name'] = abs_file_path
                            else:
                                file_metadata['merged'] = False
                            if get_md5:
                                file_metadata['md5'] = md5(abs_file_path)
                            # Use the relative file path as a key to save its metadata dictionary.
                            walk_files[relative_file_path] = file_metadata
                    except FileNotFoundError as e:
                        logger.debug(f"File {file_} was deleted in previous iteration: {e}")
                    except PermissionError as e:
                        logger.error(f"Can't read metadata from file {file_}: {e}")
            else:
                break
    except OSError as e:
        raise WazuhInternalError(3015, e)
    return walk_files


def get_files_status(data, get_md5=True):
    """Get all files and metadata inside the directories listed in cluster.json['files'].

    Parameters
    ----------
    get_md5 : bool
        Whether to calculate and save the MD5 hash of the found file.

    Returns
    -------
    final_items : dict
        Paths (keys) and metadata (values) of all the files requested in cluster.json['files'].
    """
    cluster_items = get_cluster_items()

    final_items = {}
    for file_path, item in cluster_items['files'].items():
        if file_path == "excluded_files" or file_path == "excluded_extensions":
            continue
        try:
            final_items.update(
                walk_dir(file_path, item['recursive'], item['files'], cluster_items['files']['excluded_files'],
                         cluster_items['files']['excluded_extensions'], file_path, get_md5, data))
        except Exception as e:
            logger.warning(f"Error getting file status: {e}.")

    return final_items


# def send_data_to_wdb(data, timeout):
#     """Send chunks of data to Wazuh-db socket.
#
#     Parameters
#     ----------
#     data : dict
#         Dict containing command and list of chunks to be sent to wazuh-db.
#     timeout : int
#         Seconds to wait before stopping the task.
#
#     Returns
#     -------
#     result : dict
#         Dict containing number of updated chunks, error messages (if any) and time spent.
#     """
#     result = {'updated_chunks': 0, 'error_messages': {'chunks': [], 'others': []}, 'time_spent': 0}
#     wdb_conn = WazuhDBConnection()
#     before = time()
#
#     try:
#         with Timeout(timeout):
#             for i, chunk in enumerate(data['chunks']):
#                 try:
#                     wdb_conn.send(f"{data['set_data_command']} {chunk}", raw=True)
#                     result['updated_chunks'] += 1
#                 except TimeoutError:
#                     raise e
#                 except Exception as e:
#                     result['error_messages']['chunks'].append((i, str(e)))
#     except TimeoutError:
#         result['error_messages']['others'].append('Timeout while processing agent-info chunks.')
#     except Exception as e:
#         result['error_messages']['others'].append(f'Error while processing agent-info chunks: {e}')
#
#     result['time_spent'] = time() - before
#     wdb_conn.close()
#     return result
#
#
# def unmerge_info(merge_type, path_file, filename):
#     """Unmerge one file into multiples and yield the information.
#
#     Split the information of a file like the one below, using the name (001, 002...), the modification time
#     and the content of each one:
#         8 001 2020-11-23 10:51:23
#         default
#         16 002 2020-11-23 08:50:48
#         default,windows
#
#     This function does NOT create any file, it only splits and returns the information.
#
#     Parameters
#     ----------
#     merge_type : str
#         Name of the destination directory inside queue. I.e: {wazuh_path}/queue/{merge_type}/<unmerge_files>.
#     path_file : str
#         Path to the unzipped merged file.
#     filename
#         Filename of the merged file.
#
#     Yields
#     -------
#     str
#         Splitted relative file path.
#     data : str
#         Content of the splitted file.
#     st_mtime : str
#         Modification time of the splitted file.
#     """
#     src_path = abspath(join(path_file, filename))
#     dst_path = join("queue", merge_type)
#
#     bytes_read = 0
#     total_bytes = stat(src_path).st_size
#     with open(src_path, 'rb') as src_f:
#         while bytes_read < total_bytes:
#             # read header
#             header = src_f.readline().decode()
#             bytes_read += len(header)
#             try:
#                 st_size, name, st_mtime = header[:-1].split(' ', 2)
#                 st_size = int(st_size)
#             except ValueError as e:
#                 logger.warning(f"Malformed file ({e}). Parsed line: {header}. Some files won't be synced")
#                 break
#
#             # read data
#             data = src_f.read(st_size)
#             bytes_read += st_size
#
#             yield join(dst_path, name), data, st_mtime
#
#
# def process_files_from_worker(files_metadata: Dict, decompressed_files_path: str, cluster_items: dict,
#                               worker_name: str, timeout: int):
#     """Iterate over received files from worker and updates the local ones.
#
#     Parameters
#     ----------
#     files_metadata : dict
#         Dictionary containing file metadata (each key is a filepath and each value its metadata).
#     decompressed_files_path : str
#         Filepath of the decompressed received zipfile.
#     cluster_items : dict
#         Object containing cluster internal variables from the cluster.json file.
#     worker_name : str
#         Name of the worker instance. Used to access the correct worker folder.
#     timeout : int
#         Seconds to wait before stopping the task.
#
#     Returns
#     -------
#     result : dict
#         Dict containing number of updated chunks and any error found in the process.
#     """
#     result = {'total_updated': 0, 'errors_per_folder': defaultdict(list), 'generic_errors': []}
#
#     try:
#         with Timeout(timeout):
#             for file_path, data in files_metadata.items():
#                 full_path = join(wazuh_path, file_path)
#                 item_key = data['cluster_item_key']
#
#                 # Only valid client.keys is the local one (master).
#                 if basename(file_path) == 'client.keys':
#                     raise WazuhClusterError(3007)
#
#                 # If the file is merged, create individual files from it.
#                 if data['merged']:
#                     for unmerged_file_path, file_data, file_time in unmerge_info(
#                             data['merge_type'], decompressed_files_path, data['merge_name']
#                     ):
#                         try:
#                             # Destination path.
#                             full_unmerged_name = join(wazuh_path, unmerged_file_path)
#                             # Path where to create the file before moving it to the destination path.
#                             tmp_unmerged_path = join(wazuh_path, 'queue', 'cluster', worker_name,
#                                                      basename(unmerged_file_path))
#
#                             # Format the file_data specified inside the merged file.
#                             try:
#                                 mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S.%f')
#                             except ValueError:
#                                 mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S')
#
#                             # If the file already existed, check if it is older than the one from worker.
#                             if isfile(full_unmerged_name):
#                                 local_mtime = datetime.utcfromtimestamp(int(stat(full_unmerged_name).st_mtime))
#                                 if local_mtime > mtime:
#                                     continue
#
#                             # Create file in temporal path and safe move it to the destination path.
#                             with open(tmp_unmerged_path, 'wb') as f:
#                                 f.write(file_data)
#
#                             mtime_epoch = timegm(mtime.timetuple())
#                             safe_move(tmp_unmerged_path, full_unmerged_name,
#                                             ownership=(wazuh_uid(), wazuh_gid()),
#                                             permissions=cluster_items['files'][item_key]['permissions'],
#                                             time=(mtime_epoch, mtime_epoch))
#                             result['total_updated'] += 1
#                         except TimeoutError as e:
#                             raise e
#                         except Exception as e:
#                             result['errors_per_folder'][item_key].append(str(e))
#
#                 # If the file is not 'merged' type, move it directly to the destination path.
#                 else:
#                     try:
#                         zip_path = join(decompressed_files_path, file_path)
#                         safe_move(zip_path, full_path, ownership=(wazuh_uid(), wazuh_gid()),
#                                         permissions=cluster_items['files'][item_key]['permissions'])
#                     except TimeoutError as e:
#                         raise e
#                     except Exception as e:
#                         result['errors_per_folder'][item_key].append(str(e))
#     except TimeoutError:
#         result['generic_errors'].append("Timeout processing extra-valid files.")
#     except Exception as e:
#         result['generic_errors'].append(f"Error updating worker files (extra valid): '{str(e)}'.")
#
#     return result

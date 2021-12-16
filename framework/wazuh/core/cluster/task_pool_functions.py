from calendar import timegm
from collections import defaultdict
from datetime import datetime
from os import stat
from os.path import join, basename, isfile
from time import time
from typing import Dict

from wazuh.core.cluster.cluster import unmerge_info
from wazuh.core.common import wazuh_path, wazuh_uid, wazuh_gid
from wazuh.core.exception import WazuhClusterError
from wazuh.core.utils import Timeout, safe_move
from wazuh.core.wdb import WazuhDBConnection


def send_data_to_wdb(data, timeout):
    """Send chunks of data to Wazuh-db socket.

    Parameters
    ----------
    data : dict
        Dict containing command and list of chunks to be sent to wazuh-db.
    timeout : int
        Seconds to wait before stopping the task.

    Returns
    -------
    result : dict
        Dict containing number of updated chunks, error messages (if any) and time spent.
    """
    result = {'updated_chunks': 0, 'error_messages': {'chunks': [], 'others': []}, 'time_spent': 0}
    wdb_conn = WazuhDBConnection()
    before = time()

    try:
        with Timeout(timeout):
            for i, chunk in enumerate(data['chunks']):
                try:
                    wdb_conn.send(f"{data['set_data_command']} {chunk}", raw=True)
                    result['updated_chunks'] += 1
                except TimeoutError:
                    raise e
                except Exception as e:
                    result['error_messages']['chunks'].append((i, str(e)))
    except TimeoutError:
        result['error_messages']['others'].append('Timeout while processing agent-info chunks.')
    except Exception as e:
        result['error_messages']['others'].append(f'Error while processing agent-info chunks: {e}')

    result['time_spent'] = time() - before
    wdb_conn.close()
    return result


def process_files_from_worker(files_metadata: Dict, decompressed_files_path: str, cluster_items: dict,
                              worker_name: str, timeout: int):
    """Iterate over received files from worker and updates the local ones.

    Parameters
    ----------
    files_metadata : dict
        Dictionary containing file metadata (each key is a filepath and each value its metadata).
    decompressed_files_path : str
        Filepath of the decompressed received zipfile.
    cluster_items : dict
        Object containing cluster internal variables from the cluster.json file.
    worker_name : str
        Name of the worker instance. Used to access the correct worker folder.
    timeout : int
        Seconds to wait before stopping the task.

    Returns
    -------
    result : dict
        Dict containing number of updated chunks and any error found in the process.
    """
    result = {'total_updated': 0, 'errors_per_folder': defaultdict(list), 'generic_errors': []}

    try:
        with Timeout(timeout):
            for file_path, data in files_metadata.items():
                full_path = join(wazuh_path, file_path)
                item_key = data['cluster_item_key']

                # Only valid client.keys is the local one (master).
                if basename(file_path) == 'client.keys':
                    raise WazuhClusterError(3007)

                # If the file is merged, create individual files from it.
                if data['merged']:
                    for unmerged_file_path, file_data, file_time in unmerge_info(
                            data['merge_type'], decompressed_files_path, data['merge_name']
                    ):
                        try:
                            # Destination path.
                            full_unmerged_name = join(wazuh_path, unmerged_file_path)
                            # Path where to create the file before moving it to the destination path.
                            tmp_unmerged_path = join(wazuh_path, 'queue', 'cluster', worker_name,
                                                     basename(unmerged_file_path))

                            # Format the file_data specified inside the merged file.
                            try:
                                mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S.%f')
                            except ValueError:
                                mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S')

                            # If the file already existed, check if it is older than the one from worker.
                            if isfile(full_unmerged_name):
                                local_mtime = datetime.utcfromtimestamp(int(stat(full_unmerged_name).st_mtime))
                                if local_mtime > mtime:
                                    continue

                            # Create file in temporal path and safe move it to the destination path.
                            with open(tmp_unmerged_path, 'wb') as f:
                                f.write(file_data)

                            mtime_epoch = timegm(mtime.timetuple())
                            safe_move(tmp_unmerged_path, full_unmerged_name,
                                            ownership=(wazuh_uid(), wazuh_gid()),
                                            permissions=cluster_items['files'][item_key]['permissions'],
                                            time=(mtime_epoch, mtime_epoch))
                            result['total_updated'] += 1
                        except TimeoutError as e:
                            raise e
                        except Exception as e:
                            result['errors_per_folder'][item_key].append(str(e))

                # If the file is not 'merged' type, move it directly to the destination path.
                else:
                    try:
                        zip_path = join(decompressed_files_path, file_path)
                        safe_move(zip_path, full_path, ownership=(wazuh_uid(), wazuh_gid()),
                                        permissions=cluster_items['files'][item_key]['permissions'])
                    except TimeoutError as e:
                        raise e
                    except Exception as e:
                        result['errors_per_folder'][item_key].append(str(e))
    except TimeoutError:
        result['generic_errors'].append("Timeout processing extra-valid files.")
    except Exception as e:
        result['generic_errors'].append(f"Error updating worker files (extra valid): '{str(e)}'.")

    return result

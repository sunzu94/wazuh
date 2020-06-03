#include <stdio.h>
#include <time.h> 
#include "dbsync.h"
#include <iostream>
#include <chrono>
int main() 
{
    std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `is_elevated_token` INTEGER, `elapsed_time` BIGINT, `handle_count` BIGINT, `percent_processor_time` BIGINT, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    std::string insert_sql{ "{\"table\":\"processes\",\"data\":[{\"pid\":4,\"name\":\"System\",\"path\":\"\",\"cmdline\":\"\",\"state\":\"\",\"cwd\":\"\",\"root\":\"\",\"uid\":-1,\"gid\":-1,\"euid\":-1,\"egid\":-1,\"suid\":-1,\"sgid\":-1,\"on_disk\":-1,\"wired_size\":-1,\"resident_size\":-1,\"total_size\":-1,\"user_time\":-1,\"system_time\":-1,\"disk_bytes_read\":-1,\"disk_bytes_written\":-1,\"start_time\":-1,\"parent\":0,\"pgroup\":-1,\"threads\":164,\"nice\":-1,\"is_elevated_token\":false,\"elapsed_time\":-1,\"handle_count\":-1,\"percent_processor_time\":-1}]}"};
    std::string update_sql{ "{\"table\":\"processes\",\"data\":[{\"pid\":4,\"name\":\"System\",\"path\":\"\",\"cmdline\":\"44\",\"state\":\"\",\"cwd\":\"aa\",\"root\":\"\",\"uid\":-1,\"gid\":-1,\"euid\":-1,\"egid\":-1,\"suid\":-1,\"sgid\":-1,\"on_disk\":-1,\"wired_size\":-1,\"resident_size\":-1,\"total_size\":-1,\"user_time\":-1,\"system_time\":-1,\"disk_bytes_read\":-1,\"disk_bytes_written\":-1,\"start_time\":-1,\"parent\":0,\"pgroup\":-1,\"threads\":164,\"nice\":-1,\"is_elevated_token\":false,\"elapsed_time\":-1,\"handle_count\":-1,\"percent_processor_time\":-1},{\"pid\":5,\"name\":\"System\",\"path\":\"\",\"cmdline\":\"\",\"state\":\"\",\"cwd\":\"\",\"root\":\"\",\"uid\":-1,\"gid\":-1,\"euid\":-1,\"egid\":-1,\"suid\":-1,\"sgid\":-1,\"on_disk\":-1,\"wired_size\":-1,\"resident_size\":-1,\"total_size\":-1,\"user_time\":-1,\"system_time\":-1,\"disk_bytes_read\":-1,\"disk_bytes_written\":-1,\"start_time\":-1,\"parent\":0,\"pgroup\":-1,\"threads\":164,\"nice\":-1,\"is_elevated_token\":false,\"elapsed_time\":-1,\"handle_count\":-1,\"percent_processor_time\":-1}]}"};
    cJSON * json_insert { cJSON_Parse(insert_sql.c_str()) };
    cJSON * json_update { cJSON_Parse(update_sql.c_str()) } ;
    cJSON * json_result { nullptr };
    auto handle { initialize(HostType::AGENT, DatabaseType::SQLITE3, "temp.db", sql.c_str()) };
    if (0 != handle)
    {
      if(insert_data(handle, json_insert)) {
        do {
          auto t_start {std::chrono::high_resolution_clock::now()};
          if(update_with_snapshot(handle, json_update, &json_result)) {
            auto t_end {std::chrono::high_resolution_clock::now()};
            std::cout << "duration: "<<std::chrono::duration_cast<std::chrono::microseconds>(t_end-t_start).count()<<std::endl;
            char* result_print = cJSON_Print(json_result);
            std::cout << result_print << std::endl;
            cJSON_free(result_print);
            cJSON_Delete(json_result);
          } 
        }while(getc(stdin) != 'q');
      }
      teardown();
    }
    cJSON_Delete(json_update);
    cJSON_Delete(json_insert);
    
    return 0;
}
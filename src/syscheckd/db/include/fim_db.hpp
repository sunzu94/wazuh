/**
 * @file fim_db.hpp
 * @brief
 * @date 2021-09-22
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef _FIMDB_HPP
#define _FIMDB_HPP
#include "dbsync.hpp"
#include "fim_db.hpp"
#include "rsync.hpp"
#include "shared.h"

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

enum class dbResult {
    DB_SUCESS,
    DB_ERROR
};

class EXPORTED FIMDB final
{
public:
    static FIMDB& get_instance()
    {
        static FIMDB s_instance;
        return s_instance;
    }

    void init();
    void syncDB();
    bool isFull() { return m_isFull; };
    int insertItem(DBItem);
    int removeItem(DBItem);
    int updateItem(DBItem);
    int setAllUnscanned();
    int executeQuery();

private:
    FIMDB();
    ~FIMDB() = default;
    FIMDB(const FIMDB&) = delete;
    bool m_isFull;
    DBSYNC_HANDLE m_dbsyncHandler;
    RSYNC_HANDLE m_dbsyncHandler;
};
#endif //_FIMDB_HPP

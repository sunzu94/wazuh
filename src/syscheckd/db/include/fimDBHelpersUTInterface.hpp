/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "FDBHMockInterface.hpp"
#include "dbItem.hpp"

#ifndef _FIMDB_HELPERS_UT_INTERFACE_
#define _FIMDB_HELPERS_UT_INTERFACE_

namespace FIMDBHelper
{
    template<typename T>
#ifndef WIN32

    void initDB(unsigned int sync_interval, unsigned int file_limit,
                            fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                            std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDB(sync_interval, file_limit, sync_callback, logCallback, handler_DBSync, handler_RSync);
    }
#else

    void initDB(unsigned int sync_interval, unsigned int file_limit, unsigned int registry_limit,
                             fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                             std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDB(sync_interval, file_limit, registry_limit, sync_callback, logCallback, handler_DBSync,
                              handler_RSync);
    }
#endif

    template<typename T>
    void removeFromDB(const std::string& tableName, const std::string& filter)
    {
        FIMDBHelpersMock::getInstance().removeFromDB(tableName, filter);
    }

    template<typename T>
    void getCount(const std::string & tableName, int & count)
    {

        FIMDBHelpersMock::getInstance().getCount(tableName, count);
    }

    template<typename T>
    void insertItem(const std::string & tableName, const nlohmann::json & item)
    {
        FIMDBHelpersMock::getInstance().insertItem(tableName, item);
    }

    template<typename T>
    void updateItem(const std::string & tableName, const nlohmann::json & item)
    {
        FIMDBHelpersMock::getInstance().updateItem(tableName, item);
    }

    template<typename T>
    void getDBItem(nlohmann::json & item, const nlohmann::json & query)
    {
        FIMDBHelpersMock::getInstance().getDBItem(item, query);
    }

    nlohmann::json dbQuery(const std::string & tableName, const nlohmann::json & columnList, const std::string & filter,
                 const std::string & order)
    {
        nlohmann::json query;
        query["table"] = tableName;
        query["query"]["column_list"] = columnList["column_list"];
        query["query"]["row_filter"] = filter;
        query["query"]["distinct_opt"] = false;
        query["query"]["order_by_opt"] = order;
        query["query"]["count_opt"] = 100;

        FIMDBHelpersMock::getInstance().dbQuery(tableName, columnList, filter, order);
        return query;
    }
}

#endif

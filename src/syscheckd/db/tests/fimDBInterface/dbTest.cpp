/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 8, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbTest.hpp"
#include "fimDBHelpersUTInterface.hpp"
#include "FDBHMockClass.hpp"
#include "dbsync.hpp"
#include "rsync.hpp"
#include "db.hpp"

void DBTest::SetUp () {}

void DBTest::TearDown() {}


TEST_F(DBTest, testInitDB)
{
    int sync_interval = 0;
    int file_limit = 0;
    std::shared_ptr<DBSync> handlerDbsync;
    std::shared_ptr<RemoteSync> handlerRsync;
#ifndef WIN32
    EXPECT_CALL(FIMDBHelpersMock::getInstance(), initDB(sync_interval, file_limit, testing::_, testing::_,
                                                        handlerDbsync, handlerRsync));

    fim_db_init(0, sync_interval, file_limit, NULL, NULL);
#else
    int registry_limit = 0 ;
    EXPECT_CALL(FIMDBHelpersMock::getInstance(), initDB(sync_interval, file_limit, registry_limit,
                                                        testing::_, testing::_,
                                                        handlerDbsync, handlerRsync));

    FIMDBHelper::initDB<FIMDBMock>(sync_interval, file_limit, value_limit, sync_callback, log_callback, dbsyncHandler,
                               rsyncHandler);
#endif
}

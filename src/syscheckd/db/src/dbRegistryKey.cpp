/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbRegistryKey.hpp"

void RegistryKey::createFimEntry(fim_entry& fim)
{
    fim_registry_key* key = fim.registry_entry.key;

    fim.type = FIM_TYPE_REGISTRY;
    key->id = std::atoi(m_identifier.c_str());
    key->arch = m_arch;
    std::strncpy(key->checksum, m_checksum.c_str(), sizeof(key->checksum));
    key->gid = reinterpret_cast<char*>(std::calloc(std::to_string(m_gid).length()+1, sizeof(char)));
    std::strncpy(key->gid, std::to_string(m_gid).c_str(), std::to_string(m_gid).size()+1);
    key->group_name = reinterpret_cast<char*>(std::calloc(m_groupname.length()+1, sizeof(char)));
    std::strncpy(key->group_name, m_groupname.c_str(), m_groupname.length()+1);
    key->last_event = m_lastEvent;
    key->mtime = m_time;
    key->path = reinterpret_cast<char*>(std::calloc(m_path.length()+1, sizeof(char)));
    std::strncpy(key->path, m_path.c_str(), m_path.length()+1);
    key->perm = reinterpret_cast<char*>(std::calloc(m_perm.length()+1, sizeof(char)));
    std::strncpy(key->perm, m_perm.c_str(), m_perm.length()+1);
    key->scanned =  m_scanned;
    key->uid = reinterpret_cast<char*>(std::calloc(std::to_string(m_uid).length()+1, sizeof(char)));
    std::strncpy(key->uid, std::to_string(m_uid).c_str(), std::to_string(m_uid).length()+1);
    key->user_name = reinterpret_cast<char*>(std::calloc(m_username.length()+1, sizeof(char)));
    std::strncpy(key->user_name, m_username.c_str(), m_username.length()+1);

}

void RegistryKey::createJSON()
{
    nlohmann::json conf = {};

    conf.push_back(nlohmann::json::object_t::value_type("arch", m_arch));
    conf.push_back(nlohmann::json::object_t::value_type("id", m_identifier));
    conf.push_back(nlohmann::json::object_t::value_type("last_event", m_lastEvent));
    conf.push_back(nlohmann::json::object_t::value_type("scanned", m_scanned));
    conf.push_back(nlohmann::json::object_t::value_type("checksum", m_checksum));
    conf.push_back(nlohmann::json::object_t::value_type("path", m_path));
    conf.push_back(nlohmann::json::object_t::value_type("perm", m_perm));
    conf.push_back(nlohmann::json::object_t::value_type("uid", m_uid));
    conf.push_back(nlohmann::json::object_t::value_type("gid", m_gid));
    conf.push_back(nlohmann::json::object_t::value_type("user_name", m_username));
    conf.push_back(nlohmann::json::object_t::value_type("group_name", m_groupname));
    conf.push_back(nlohmann::json::object_t::value_type("mtime", m_time));

    m_statementConf = std::make_unique<nlohmann::json>(conf);
}

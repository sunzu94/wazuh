/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbRegistryValue.hpp"

void RegistryValue::createFimEntry(fim_entry& fim)
{
    fim.type = FIM_TYPE_REGISTRY;
    fim.registry_entry.value->size = m_size;
    fim.registry_entry.value->id = m_keyUid;
    fim.registry_entry.value->name = reinterpret_cast<char*>(std::calloc(m_identifier.length()+1, sizeof(char)));;
    std::strncpy(fim.registry_entry.value->name, m_identifier.c_str(), m_identifier.length()+1);
    std::strncpy(fim.registry_entry.value->hash_md5, m_md5.c_str(), sizeof(fim.registry_entry.value->hash_md5));
    std::strncpy(fim.registry_entry.value->hash_sha1, m_sha1.c_str(), sizeof(fim.registry_entry.value->hash_sha1));
    std::strncpy(fim.registry_entry.value->hash_sha256, m_sha256.c_str(), sizeof(fim.registry_entry.value->hash_sha256));
    fim.registry_entry.value->mode = m_mode;
    fim.registry_entry.value->last_event = m_lastEvent;
    fim.registry_entry.value->scanned = m_scanned;
    std::strncpy(fim.registry_entry.value->checksum, m_checksum.c_str(), sizeof(fim.registry_entry.value->checksum));
}

void RegistryValue::createJSON()
{
    nlohmann::json conf = {};

    conf.push_back(nlohmann::json::object_t::value_type("id", m_keyUid));
    conf.push_back(nlohmann::json::object_t::value_type("mode", m_mode));
    conf.push_back(nlohmann::json::object_t::value_type("last_event", m_lastEvent));
    conf.push_back(nlohmann::json::object_t::value_type("scanned", m_scanned));
    conf.push_back(nlohmann::json::object_t::value_type("name", m_identifier));
    conf.push_back(nlohmann::json::object_t::value_type("checksum", m_checksum));
    conf.push_back(nlohmann::json::object_t::value_type("size", m_size));
    conf.push_back(nlohmann::json::object_t::value_type("hash_md5", m_md5));
    conf.push_back(nlohmann::json::object_t::value_type("hash_sha1", m_sha1));
    conf.push_back(nlohmann::json::object_t::value_type("hash_sha256", m_sha256));
    conf.push_back(nlohmann::json::object_t::value_type("type", m_type));
    m_statementConf = std::make_unique<nlohmann::json>(conf);
}

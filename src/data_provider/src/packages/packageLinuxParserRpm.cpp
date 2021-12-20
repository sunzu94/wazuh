
#include "packageLinuxDataRetriever.h"
#include "iberkeleyDbWrapper.h"
#include "berkeleyRpmDbHelper.h"
#include "sharedDefs.h"
#include "packageLinuxParserHelper.h"
#include "filesystemHelper.h"
#include "rpmlib.h"

void getRpmInfo(std::function<void(nlohmann::json&)> callback)
{

    const auto rpmDefaultQuery
    {
        [](std::function<void(nlohmann::json&)> cb)
        {
            auto rawRpmPackagesInfo{ UtilsWrapper::exec("rpm -qa --qf '%{name}\t%{arch}\t%{summary}\t%{size}\t%{epoch}\t%{release}\t%{version}\t%{vendor}\t%{installtime:date}\t%{group}\t\n'") };

            if (!rawRpmPackagesInfo.empty())
            {
                auto rows { Utils::split(rawRpmPackagesInfo, '\n') };

                for (auto row : rows)
                {
                    auto package = PackageLinuxHelper::parseRpm(row);

                    if (!package.empty())
                    {
                        cb(package);
                    }
                }
            }
        }
    };

    if (!UtilsWrapper::existsRegular(RPM_DATABASE))
    {
        // We are probably using RPM >= 1.17 – get the packages from librpm.
        try
        {
            RpmPackageManager rpm{std::make_shared<RpmLib>()};

            for (const auto& p : rpm)
            {
                auto packageJson = PackageLinuxHelper::parseRpm(p);

                if (!packageJson.empty())
                {
                    callback(packageJson);
                }
            }
        }
        catch (...)
        {
            rpmDefaultQuery(callback);
        }

    }
    else
    {
        try
        {
            BerkeleyRpmDBReader db {std::make_shared<BerkeleyDbWrapper>(RPM_DATABASE)};
            auto row = db.getNext();

            // Get the packages from the Berkeley DB.
            while (!row.empty())
            {
                auto package = PackageLinuxHelper::parseRpm(row);

                if (!package.empty())
                {
                    callback(package);
                }

                row = db.getNext();
            }
        }
        catch (...)
        {
            rpmDefaultQuery(callback);
        }

    }



}

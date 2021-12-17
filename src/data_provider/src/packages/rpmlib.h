#include "rpmlibWrapper.h"

class RpmLib final : public IRpmLibWrapper
{
    public:
        int rpmReadConfigFiles(const char* file, const char* target) override
        {
            return ::rpmReadConfigFiles(file, target);
        }

        void rpmFreeRpmrc() override
        {
            ::rpmFreeRpmrc();
        }

        rpmtd rpmtdNew() override
        {
            return ::rpmtdNew();
        }

        void rpmtdFree(rpmtd td) override
        {
            ::rpmtdFree(td);
        }

        rpmts rpmtsCreate() override
        {
            return ::rpmtsCreate();
        }

        int rpmtsOpenDB(rpmts ts, int dbmode) override
        {
            return ::rpmtsOpenDB(ts, dbmode);
        }

        int rpmtsCloseDB(rpmts ts) override
        {
            return ::rpmtsCloseDB(ts);
        }

        rpmts rpmtsFree(rpmts ts) override
        {
            return ::rpmtsFree(ts);
        }

        int headerGet(Header h, rpmTagVal tag, rpmtd td, headerGetFlags flags) override
        {
            return ::headerGet(h, tag, td, flags);
        }

        const char* rpmtdGetString(rpmtd td) override
        {
            return ::rpmtdGetString(td);
        }

        uint64_t rpmtdGetNumber(rpmtd td) override
        {
            return ::rpmtdGetNumber(td);
        }

        int rpmtsRun(rpmts ts, rpmps okProbs, rpmprobFilterFlags ignoreSet) override
        {
            return ::rpmtsRun(ts, okProbs, ignoreSet);
        }

        rpmdbMatchIterator rpmtsInitIterator(const rpmts ts, rpmDbiTagVal rpmtag, const void* keypointer, size_t keylen) override
        {
            return ::rpmtsInitIterator(ts, rpmtag, keypointer, keylen);
        }

        Header rpmdbNextIterator(rpmdbMatchIterator mi) override
        {
            return ::rpmdbNextIterator(mi);
        }

        rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi) override
        {
            return ::rpmdbFreeIterator(mi);
        }
};
#ifndef TopologyProbeBridge_h
#define TopologyProbeBridge_h

#ifdef __cplusplus
extern "C" {
#endif

const char *TEPCopyProbeReport(void);
void TEPFreeProbeReport(const char *report);

#ifdef __cplusplus
}
#endif

#endif

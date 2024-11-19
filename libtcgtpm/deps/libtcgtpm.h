#pragma once

typedef unsigned int uint32_t;
void _plat__RunCommand(
    uint32_t         requestSize,   // IN: command buffer size
    unsigned char   *request,       // IN: command buffer
    uint32_t        *responseSize,  // IN/OUT: response buffer size
    unsigned char   **response      // IN/OUT: response buffer
);

void _plat__LocalitySet(unsigned char locality);
void _plat__SetNvAvail(void);
int  _plat__Signal_PowerOn(void);
int  _plat__Signal_Reset(void);
void _plat__NVDisable(int delete);
int  _plat__NVEnable(void *platParameter);

int  TPM_Manufacture(int firstTime);
int  TPM_TearDown(void);
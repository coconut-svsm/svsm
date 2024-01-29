#pragma once

void _plat__LocalitySet(unsigned char locality);
void _plat__SetNvAvail(void);
int  _plat__Signal_PowerOn(void);
int  _plat__Signal_Reset(void);
void _plat__NVDisable(int delete);
int  _plat__NVEnable(void *platParameter);

int  TPM_Manufacture(int firstTime);
int  TPM_TearDown(void);
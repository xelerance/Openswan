#ifndef PLUTO_VENDORID_SIZE
#define PLUTO_VENDORID_SIZE 12
#endif
void init_fake_vendorid()
{
	strcpy(pluto_vendorid, "OEplutounit0");
        pluto_vendorid[PLUTO_VENDORID_SIZE] = '\0';
}


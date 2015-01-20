#define PLUTO_VENDORID_SIZE 12
char pluto_vendorid[PLUTO_VENDORID_SIZE + 1];

void init_fake_vendorid()
{
	strcpy(pluto_vendorid, "OEplutounit0");
        pluto_vendorid[PLUTO_VENDORID_SIZE] = '\0';
}

const char *
init_pluto_vendorid(void)
{
  init_fake_vendorid();
}

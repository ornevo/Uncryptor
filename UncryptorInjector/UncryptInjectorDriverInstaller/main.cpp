#include "install.h"
#include <iostream>
bool Install()
{
	TCHAR driverLocation[MAX_PATH] = { 0 };
	if (!SetupDriverName(driverLocation, sizeof(driverLocation)))
	{
		return false;
	}

	if (!ManageDriver(TEXT(DRIVER_NAME), driverLocation, DRIVER_FUNC_INSTALL))
	{
		std::cout << "[UncryptInstaller]: Error at install\n";
		ManageDriver(TEXT(DRIVER_NAME), driverLocation, DRIVER_FUNC_REMOVE);
		return false;
	}
	return true;

}

bool Uninstall()
{
	TCHAR driverLocation[MAX_PATH] = { 0 };
	if (!SetupDriverName(driverLocation, sizeof(driverLocation)))
	{
		return false;
	}
	ManageDriver(TEXT(DRIVER_NAME), driverLocation, DRIVER_FUNC_REMOVE);
	return true;
}
void help()
{
	std::cout << "Usage: UncryptInstaller -i / -u\n";
	std::cout << "-i Install" << std::endl << "-u Uninstall" << std::endl;
}
int main(int argc, char* argv[])
{
	if (argc == 2)
	{
		if (!strcmp(argv[1], "-i"))
		{
			if (Install())
			{
				std::cout << "[UncryptInstaller]: Installed the driver successfully" << std::endl;
			}
			else
			{
				std::cout << "[UncryptInstaller]: Couldnt install driver" << std::endl;
			}
		}
		else if(!strcmp(argv[1], "-u"))
		{
			if (Uninstall())
			{
				std::cout << "[UncryptInstaller]: Uninstalled the driver successfully" << std::endl;
			}
			else
			{
				std::cout << "[UncryptInstaller]: Couldnt uninstall driver" << std::endl;
			}
		}
		else
		{
			help();
		}
	}
	else
	{
		help();
	}
}
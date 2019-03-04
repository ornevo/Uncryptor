#include "Manager.h"

bool Manager::m_is_created = false;
Manager * Manager::m_instance = nullptr;

Manager::Manager(): m_hooker(std::make_unique<Hooker>())
{

}


Manager::~Manager()
{
}

Manager * Manager::GetInstance()
{
	if (!m_is_created)
	{
		m_instance = new Manager();
		m_is_created = true;
	}
	return m_instance;
}
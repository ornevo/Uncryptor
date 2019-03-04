#pragma once
#include "Manager.h"
#include "Hooker.h"
#include <memory>
class Manager
{
private:
	std::unique_ptr<Hooker> m_hooker;
	static Manager * m_instance;
	static bool m_is_created;
	Manager();
	~Manager();
public:
	
	static Manager* GetInstance();
	
};


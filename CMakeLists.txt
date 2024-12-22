cmake_minimum_required(VERSION 3.5)

project(KriptaKursach VERSION 0.1 LANGUAGES CXX)

# Включение текущей директории для поиска заголовочных файлов
set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Автоматическое подключение для Qt
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Устанавливаем стандарт C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск зависимостей

# Поиск библиотеки libarchive
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)

# Поиск библиотеки libtar
find_path(LIBTAR_INCLUDE_DIR NAMES tar.h PATHS /usr/include /usr/local/include)
find_library(LIBTAR_LIBRARY NAMES tar PATHS /usr/lib /usr/local/lib)

# Поиск OpenSSL
find_package(OpenSSL REQUIRED)

# Поиск Qt
find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)

# Список исходных файлов
set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    entropy.ui
    entropy.h
    entropy.cpp
    Crypto.h
    Crypto.cpp
    actionwithcontainer.h actionwithcontainer.cpp actionwithcontainer.ui
    base64.h base64.cpp
)

# Создаем исполнимый файл, учитывая, какая версия Qt используется
if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(KriptaKursach
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(KriptaKursach SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(KriptaKursach
            ${PROJECT_SOURCES}
        )
    endif()
endif()

# Связываем библиотеки с проектом
target_link_libraries(KriptaKursach PRIVATE Qt${QT_VERSION_MAJOR}::Widgets OpenSSL::Crypto OpenSSL::SSL)

# Связываем libarchive
target_link_libraries(KriptaKursach PRIVATE ${LIBARCHIVE_LIBRARIES})

# Проверяем наличие библиотеки libtar и добавляем её
if(LIBTAR_INCLUDE_DIR AND LIBTAR_LIBRARY)
    include_directories(${LIBTAR_INCLUDE_DIR})
    target_link_libraries(KriptaKursach PRIVATE ${LIBTAR_LIBRARY})
else()
    message(FATAL_ERROR "libtar not found!")
endif()

# Дополнительные свойства для MacOSX
set_target_properties(KriptaKursach PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Финализация проекта для Qt6
if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(KriptaKursach)
endif()

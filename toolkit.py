#!/usr/bin/env python3
import logging
import os
from argparse import ArgumentParser
from pathlib import Path

from git.repo.base import Repo


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument('--search', dest='search', required=False,
                        help='Optional. A query to search within the toolkit.')
    parser.add_argument('--download', dest='download', required=False,
                        help='Optional. Download a tool by it\'s name. The tool will be downloaded in a newly created '
                             'directory. Pass DOWNLOAD_ALL to download everything.')
    parser.add_argument('--update', dest='update', required=False, help='Optional. Update a given tool. '
                                                                        'Pass UPDATE_ALL to update all downloaded '
                                                                        'tools')
    parser.add_argument('--show', dest='show', required=False,
                        help='Optional. Show details about the downloaded tool.')
    parser.add_argument('--drop-deprecated', action='store_true', required=False,
                        help='Optional. Define when the toolkit should clean up deprecated tools (a tool will be '
                             'marked as deprecated when it doesn\'t stored anymore in the root README.md file)')
    parser.add_argument('--logging', dest='logging', choices=['INFO', 'DEBUG', 'WARNING', 'ERROR'], default='INFO',
                        help='Optional. Logging level.')
    options = parser.parse_args()

    return options


class colors:
    BLACK = "\u001b[30m"
    PALE_RED = "\u001b[31m"
    PALE_GREEN = "\u001b[32m"
    PALE_YELLOW = "\u001b[33m"
    PALE_BLUE = "\u001b[34m"
    PALE_MAGENTA = "\u001b[35m"
    PALE_CYAN = "\u001b[36m"

    GRAY = "\u001b[90m"
    RED = "\u001b[91m"
    GREEN = "\u001b[92m"
    YELLOW = "\u001b[93m"
    BLUE = "\u001b[94m"
    MAGENTA = "\u001b[95m"
    CYAN = "\u001b[96m"
    WHITE = "\u001b[97m"

    BG_GRAY = "\u001b[100m"
    BG_RED = "\u001b[41m"
    BG_GREEN = "\u001b[42m"
    BG_YELLOW = "\u001b[43m"
    BG_BLUE = "\u001b[44m"
    BG_MAGENTA = "\u001b[45m"
    BG_CYAN = "\u001b[46m"
    BG_WHITE = "\u001b[47m"

    BOLD = "\u001b[1m"
    RESET = "\u001b[0m"

    @staticmethod
    def colored(text, color=WHITE):
        return f"{color}{text}{colors.RESET}"

    @staticmethod
    def print_colored(text, color=WHITE):
        print(colors.colored(text, color))

    @staticmethod
    def red(text):
        return colors.colored(text, colors.RED)

    @staticmethod
    def green(text):
        return colors.colored(text, colors.GREEN)

    @staticmethod
    def yellow(text):
        return colors.colored(text, colors.YELLOW)

    @staticmethod
    def bold(text):
        return colors.colored(text, colors.BOLD)

    @staticmethod
    def print_red(text):
        colors.print_colored(text, colors.RED)

    @staticmethod
    def print_bold(text):
        print(colors.bold(text))

    @staticmethod
    def print_green(text):
        print(colors.green(text))


"""
   Download tools asynchronously
"""

import time
import platform
import asyncio
from enum import Enum


class SynchronizationMode(Enum):
    DOWNLOAD = "DOWNLOAD",
    UPDATE = "UPDATE"


class BatchAsyncDownloader:
    def __init__(self):
        pass

    """
       Updates a list of tools
    """

    def update_tools(self, tools: list):
        self.generate_and_run_commands(
                    [t for t in tools if t.is_downloaded() and t.is_git_repository()],
                    SynchronizationMode.UPDATE)

    """
       Clones a list of tools
    """

    def download_tools(self, tools: list):
        self.generate_and_run_commands(
                    [t for t in tools if not t.is_downloaded() and any(host in t.url for host in git_sources)],
                    SynchronizationMode.DOWNLOAD)

    """
       Spawn a process to download/update a tool
    """

    async def sync_tool(self, mode: SynchronizationMode, tool):
        """
           Run tool synchronization in subprocess
        """

        if mode == SynchronizationMode.DOWNLOAD:
            tool.path.mkdir(parents=True, exist_ok=True)
            command = ['git', 'clone', tool.url, str(tool.path)]
        elif mode == SynchronizationMode.UPDATE:
            command = ['git', '-C', str(tool.path), 'pull']
        else:
            raise Exception("Unsupported synchornization mode: " + str(mode))

        logging.debug('Executing %s command: %s', mode, str(command))
        process = await asyncio.create_subprocess_exec(
                    *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        tool_name = tool.name

        if mode == SynchronizationMode.DOWNLOAD:
            logging.info('Downloading %s', tool_name)
        if mode == SynchronizationMode.UPDATE:
            logging.info('Updating %s', tool_name)

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            if mode == SynchronizationMode.DOWNLOAD:
                logging.info(colors.green('{} has been downloaded'.format(tool_name)))
            if mode == SynchronizationMode.UPDATE:
                logging.info(colors.green('{} has been updated'.format(tool_name)))

        else:
            if mode == SynchronizationMode.DOWNLOAD:
                logging.error(colors.red("{} failed to download".format(tool_name)))
                logging.debug('{}: {} / {}'.format(tool_name, stdout, stderr))
            if mode == SynchronizationMode.UPDATE:
                logging.error(colors.red("{} failed to update".format(tool_name)))
                logging.debug('{}: {} / {}'.format(tool_name, stdout, stderr))
        result = stdout.decode().strip()

        return result

    def generate_and_run_commands(self, tools: list, mode: SynchronizationMode):
        start_time = time.time()
        logging.debug('%s tool(s) received for %s', len(tools), mode)
        tasks = []
        for tool in tools:
            result = self.sync_tool(mode, tool)
            tasks.append(result)

        def run_asyncio_commands(tasks, max_concurrent_tasks=0):
            def make_chunks(l, n):
                """Yield successive n-sized chunks from l.

                Note:
                    Taken from https://stackoverflow.com/a/312464
                """
                for i in range(0, len(l), n):
                    yield l[i: i + n]

            """Run tasks asynchronously using asyncio and return results.

            If max_concurrent_tasks are set to 0, no limit is applied.

            Note:
                By default, Windows uses SelectorEventLoop, which does not support
                subprocesses. Therefore ProactorEventLoop is used on Windows.
                https://docs.python.org/3/library/asyncio-eventloops.html#windows
            """
            all_results = []

            if max_concurrent_tasks == 0:
                chunks = [tasks]
                num_chunks = len(chunks)
            else:
                chunks = make_chunks(l=tasks, n=max_concurrent_tasks)
                num_chunks = len(list(make_chunks(l=tasks, n=max_concurrent_tasks)))

            if asyncio.get_event_loop().is_closed():
                asyncio.set_event_loop(asyncio.new_event_loop())
            if platform.system() == "Windows":
                asyncio.set_event_loop(asyncio.ProactorEventLoop())
            loop = asyncio.get_event_loop()

            for i, tasks_in_chunk in enumerate(chunks):
                chunk = i + 1
                logging.debug(f"Beginning work on chunk {chunk}/{num_chunks}")
                commands = asyncio.gather(*tasks_in_chunk)
                # TODO queueing instead of chunking?
                results = loop.run_until_complete(commands)
                all_results += results
                logging.debug(f"Completed work on chunk {chunk}/{num_chunks}")

            loop.close()
            return all_results

        results = run_asyncio_commands(tasks, max_concurrent_tasks=20)  # At most 20 parallel tasks
        logging.debug("Results: " + os.linesep.join(results))

        if len(results) > 0:
            end = time.time()
            rounded_end = "{0:.4f}".format(round(end - start_time, 4))
            logging.info(
                        f"Async tools {'downloader' if mode == SynchronizationMode.DOWNLOAD else 'updater'} ran in "
                        f"about" +
                        f" {rounded_end} seconds")


options = get_arguments()

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=options.logging)

git_sources = [
    'github.com',
    'bitbucket.com'
]

prefix = colors.colored('/red-toolkit $ ', colors.RED)


class Tool:
    @staticmethod
    def find_category(url, readme_file):
        with open(readme_file, 'r', encoding='utf-8') as file:
            sections = file.read().split('## ')
            for sec in sections:
                if url in sec:
                    category = sec.split(os.linesep)[0]
                    return {
                        'name': category,
                        'alias': category.lower().replace(' ', '-')
                    }

    @staticmethod
    def fetch_tool_readme(tool_path, tool_name):
        readme_files_candidates = ['README.md', 'README', 'README.MD', 'readme', 'readme.md']
        for readme in readme_files_candidates:
            readme_path = str(tool_path) + '/' + readme
            if os.path.exists(readme_path):
                logging.debug('README file has been extracted for %s', tool_name)
                return open(readme_path, 'r', encoding='utf-8').read()

    def __init__(self, line, file_content_as_string):
        assert line and line.strip() != ''
        self.name = line.split('**')[1].split('**')[0]
        self.description = line.split('**')[2].split('http')[0].strip()
        self.url = line.split(' ')[-1]
        self.category = self.find_category(self.url, file_content_as_string)
        self.path = Path(os.getcwd() + '/' + self.category['alias'] + '/' + self.name)
        self.tool_readme = self.fetch_tool_readme(str(self.path), self.name) if self.is_downloaded() else None

    def is_downloaded(self):
        return os.path.exists(self.path) and os.listdir(self.path)

    def is_git_repository(self):
        try:
            return Repo(self.path) != None
        except:
            return False

    def update(self):
        if not self.is_downloaded():
            logging.debug(colors.red('{} is not downloaded'.format(self.name)))
            return
        try:
            Repo(self.path).remote().pull()
            logging.info(colors.green('{} has been updated'.format(self.name)))
        except Exception as e:
            logging.error(colors.red('Update failed: ' + str(e)))

    def printout(self, verbose=False):
        colors.print_red(colors.bold(self.name) + ' // ' + self.category['name'])
        colors.print_bold(
                    colors.green('DOWNLOADED - ' + colors.RESET + colors.yellow(str(self.path))) if self.is_downloaded()
                    else colors.colored('NOT_DOWNLOADED', colors.MAGENTA))
        print(self.url)
        colors.print_bold(self.description)
        if verbose:
            if self.tool_readme:
                print(self.tool_readme)

    def use(self):
        print('Switching to ' + self.name)
        print(self.path)

        # FIXME: port to windows?
        os.chdir(self.path)
        os.environ['PS1'] = colors.red(f"[$PWD]\n{self.category['alias']}/{self.name} >> ")
        os.system('/bin/sh -i')


def download_tool(tool_name, tools):
    tools_to_download_list = []

    for tool in tools:
        if tool.name == tool_name or tool_name == 'DOWNLOAD_ALL':
            tools_to_download_list.append(tool)
    asyncgit = BatchAsyncDownloader()
    asyncgit.download_tools(tools_to_download_list)


def update_tool(tool_name, tools):
    tools_to_update_list = []
    for tool in tools:
        if tool.name == tool_name or tool_name == 'UPDATE_ALL':
            tools_to_update_list.append(tool)
    asyncgit = BatchAsyncDownloader()
    asyncgit.update_tools(tools_to_update_list)


def show_tool_info(tool_name, tools):
    tool_found = False
    for tool in tools:
        if tool_name == tool.name:
            tool_found = True
            tool.printout(True)
    if not tool_found:
        logging.error(colors.red('%s wasn\'t found in the toolkit context' % tool_name))


def use_tool(tool_name, tools):
    for tool in tools:
        if tool_name == tool.name:
            tool.use()


def get_tools_from_readme(readme_file):
    tools = []
    with open(readme_file, 'r', encoding='utf-8') as file:
        lines = [line.replace(os.linesep, '') for line in file.readlines()]
        for line in lines:
            if line.startswith('* **'):
                tool = Tool(line, readme_file)
                tools.append(tool)
    return tools


def get_scripts_from_readme(readme_file):
    scripts_url = []
    with open(readme_file, 'r', encoding='utf-8') as file:
        file_content_as_string = [line.replace(os.linesep, '') for line in file.readlines()]
        for line in file_content_as_string:
            if line.startswith('  * '):
                scripts_url.append(line.replace('  * ', ''))
    return scripts_url


def interact(tools):
    def search(command, tools):
        query = command.replace('search ', '')
        search_in_tools(query, tools)

    def download(command, tools):
        tool_name = command.replace('download ', '')
        download_tool(tool_name, tools)

    def update(command, tools):
        tool_name = command.replace('update ', '')
        update_tool(tool_name, tools)

    def show(command, tools):
        tool_name = command.replace('show ', '')
        show_tool_info(tool_name, tools)

    def use(command, tools):
        tool_name = command.replace('use ', '')
        use_tool(tool_name, tools)

    def help():
        print('search <case insensitive query> "search dns"')
        print('download <tool name> "download SharpSploit"/"download DOWNLOAD_ALL"')
        print('update <tool name> "update SharpSploit"/"update UPDATE_ALL"')
        print('show <tool name> "show SharpSploit"')
        print('use <tool name> "use SharpSploit"')

    while True:
        command = input(prefix)
        if command == 'exit':
            exit(0)
        if command == 'help' or command == '?':
            help()
        if command.startswith('search '):
            search(command, tools)
        if command.startswith('download '):
            download(command, tools)
        if command.startswith('update '):
            update(command, tools)
        if command.startswith('show '):
            show(command, tools)
        if command.startswith('use '):
            use(command, tools)


def print_categories(tools):
    categories = {}
    for tool in tools:
        category = tool.category['name']
        if category in categories:
            categories[category] += 1
        else:
            categories[category] = 1
    colors.print_bold('Categories:')
    for category, entries in dict([(k, categories[k]) for k in
                                   sorted(categories, key=categories.get, reverse=True)]
                                  ).items():
        if entries > 0:
            colors.print_green(f'{category} - {entries} tool(s)')


def mark_deprecated_tools(synchronized_tools, categories):
    stored_tools_names = []
    deprecated_tools_names = []
    for category in categories:
        if os.path.isdir(category):
            for t in os.listdir('./' + category + '/'):
                if t.replace(os.linesep, '').strip() != '':
                    stored_tools_names.append(t)
    for tool in stored_tools_names:
        if not any(tool in sync_tool.name for sync_tool in synchronized_tools):
            logging.warning(colors.yellow('{} has been marked as deprecated'.format(tool)))
            deprecated_tools_names.append(tool)
    return deprecated_tools_names


def drop_deprecated_tools(deprecated_tools):
    import shutil

    for tool_name in deprecated_tools:
        for dir in [dir[0] for dir in os.walk(Path(os.getcwd()))]:
            if tool_name in dir:
                shutil.rmtree(Path(str(dir).split(tool_name)[0] + tool_name))
                logging.info(colors.green('{} tool has been deleted'.format(tool_name)))
                break


def search_in_tools(search, tools):
    logging.info('Searching for %s', search)
    matched_tools = []
    for tool in tools:
        pattern = search.lower()
        if pattern in tool.name.lower() \
                    or pattern in tool.description.lower() \
                    or pattern in tool.category['name'].lower():
            matched_tools.append(tool)
    matched_tools_count = len(matched_tools)
    logging.info("%s tools have been found", matched_tools_count)
    if matched_tools_count > 0:
        print_categories(matched_tools)
    for tool in matched_tools:
        tool.printout()
        colors.print_bold('*' * 60)


if __name__ == "__main__":
    colors.print_bold("""
NNNNNNNNNNNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNNNNNNNN
NNNNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNNNNN
NNNNNNNNNNNNNNmmmdhddmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNNN
NNNNNNNNNNNNNmmmmmmmmhyyhdmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNN
NNNNNNNNNNNmmmmmmmmmmmmmdyssydmmmmmmmmmmmmddmmdmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNN
NNNNNNNNNNNmmmmmmmmmmmmmmmmmhs+sydmmmmmmmmmmddmmdddmmmmmmmmmmmmmmmmmmmmNNNNNNN
hhhhhhhhhhhdddmmmmmmmmmmmmmmmmmhs++sdmmmmmmmmddddmmddmmmmmmmmmmmmmmmmmmNNNNNNN
dhhhhyyyyssssooosssyhdmmmmmmmmmmmmds//ohmmmmmmmdddddmdddmmmmmmmmmmmmmmmmNNNNNN
hhyyyyyyssoosoo+++/////oydmddmmmmddddhs//sddmmmmmmdddddmmmmmmmmmmmmmmmmmmNNNNN
ddddddddhhysooo+++////:/::++:ohmmdddddddh+-+ydmmmmmddddmdddmmmmmmmmmmmmmmmNNNN
NNNNNmmmmmmmmmdhyyo+/:::::::---/sdo/hdddddds::sdddmmmddddmmmmmmmmmmmmmmmmmNNNN
NNNNNmmmmmmmmmmmmmmmmdhyo+:---:------+hdddoydy:-oddmmmmdddmmmmmmmmmmmmmmmmmNNN
NNNNNmmmmmmmmmmmmmmmmmmmmmdhso/--......:oy+-/hds:-oddmmmmmddmmmmmmmmmmmmmmmNNN
NNNNNmmmmmmmmmmmmmmmmmmmmmddddddys/:...--...--sddooyddmmmmmmddmmmmmmmmmmmmmmmN
NNNNmmmmmmmmmmmmmmmmmmmmmmmddddddddddyo/-.-.---+ssssshmmmmmmmmddmmmmmmmmmmmmNm
NNNNNmmmmmmmmmmmmmmmmmmmmmmddddddddddddddhs+:--------:ymmmmmmmmmmmmmmmmmmmmmmm
NNNNNmmmmmmmmmmmmmmmmmmmmmmmdddddddddddddddddo--:-----:ommmmmmmmmmmmmmmmmmmmmN
NNNNNmmmmmmmmmmmmmmmmmmmmmmmdddddddddddddddddo--:----++-+dmmmmmmmmmmmmmmmmmmmm
NNNNNmmmmmmmmmmmmmmmmmmmmmmmmmdddddddddddddddh:----:--//:/hmmmmmmmmmmmmmmmmmmm
NNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmddddddddddddddddyo/-:::::::smmmmmmmmmmmmmmmmNNN
NNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmddddddddddddddddmdhs+:/://+hmmmmmmmmmmmmmmmNN
NNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmdy+////+ydmmmmmmmmNNNNmm
NNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmds+++++syhdmmmNNNNNNN
NNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmyo++shdmmmmNNNNNNN
NNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmhymmmmmNNNNNNNNN
NNNNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNN
NNNNNNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNNN
NNNNNNNNNNNNNNNmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmNNNNNNNNNNNNN
    """)

    readme = 'README.md'

    scripts = get_scripts_from_readme(readme)
    tools = get_tools_from_readme(readme)
    downloaded_tools = [t for t in tools if t.is_downloaded()]
    categories = set([t.category['alias'] for t in tools])

    # check for the deprecated tools
    deprecated_tools = mark_deprecated_tools(tools, categories)

    if options.drop_deprecated:
        drop_deprecated_tools(deprecated_tools)

    print(colors.bold('## red-toolkit initialized'))
    print(f'{colors.bold(len(categories))} categories')
    print(f'{colors.bold(len(tools))} tools')
    print(f'{colors.bold(len(downloaded_tools))} tools')
    print(f'{colors.bold(len(scripts))} scripts')

    try:
        if options.search:
            search_in_tools(options.search, tools)
        elif options.update:
            update_tool(options.update, tools)
        elif options.download:
            download_tool(options.download, tools)
        elif options.show:
            show_tool_info(options.show, tools)
        else:
            interact(tools)
    except KeyboardInterrupt:
        logging.info('Keyboard interrupt, exiting')
        exit(0)
    # except Exception as e:
    #     logging.error(colors.red('Unexpected error: ' + str(e)))

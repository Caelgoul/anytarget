#!/usr/bin/env python3

import re
import os
import csv
import json
import click
import requests
from tqdm import tqdm
from tabulate import tabulate
from collections import defaultdict
from tempfile import gettempdir


__author__ = "Mohamed Qasim 1997"
__version__ = "1.0.0"




def init(apikey):
   path = os.path.join(gettempdir(), "anytarget.io")
   tmp = open(path, "w")
   tmp.write(apikey+"\n")
   tmp.close()
   # make group can read it
   if os.geteuid() == 0:
      os.chmod(path, 0o777)


def get_apikey():
   path = os.path.join(gettempdir(), "anytarget.io")
   tmp = open(path, "r+")
   apikey = tmp.readline().strip()
   tmp.close()
   return apikey


def highlight(string:str, word:str) -> str:
   # index matched word
   wlen = len(word)
   indx = string.lower().index(word.lower())
   # take matched line
   for string in string.splitlines():
      if word in string : break
   # remove tap spaces
   string = string.replace("\t", " ")
   # shortcuting string
   if wlen+indx > 45 :
      frm = indx      - (50//2)
      end = indx+wlen + (50//2)
   else:
      frm = 0
      end = 50
   # get shortcut and heighlight matched string
   string = "".join([
      string[frm:indx],           # from pos to matched word
      "\033[31m",                 # start color
      string[indx:indx+wlen],     # from word to end word
      "\033[0m",                  # end color
      string[indx+wlen:end]       # from end word to end
      ])
   return string


def find_matched_port(key:str, value:str, data:dict, hlight:bool) -> list:
   matchedlist = []
   for port in data["ports"] :
      #data.pop("cpe", "")
      cpes    = port.pop("cpe", [])
      scripts = port.pop("script", {}).values()
      match key:
         case "text" :
            if value.lower() in port.get("service", ".").lower() :
               if hlight :
                  port["service"] = highlight(port["service"], value)
               matchedlist.append(data | port)
            elif   value.lower() in port.get("product", ".").lower() :
               if hlight :
                  port["product"] = highlight(port["product"], value)
               matchedlist.append(data | port)
            elif value.lower() in port.get("version", ".").lower() :
               if hlight :
                  port["version"] = highlight(port["version"], value)
               matchedlist.append(data | port)
            elif value.lower() in port.get("info", ".").lower() :
               if hlight :
                  port["info"] = highlight(port["info"], value)
               matchedlist.append(data | port)
            elif value.lower() in port.get("os", ".").lower() :
               if hlight :
                  port["os"] = highlight(port["os"], value)
               matchedlist.append(data | port)
            elif value.lower() in port.get("cpe", ".").lower() :
               if hlight :
                  port["cpe"] = highlight(port["cpe"], value)
               matchedlist.append(data | port)
            elif  value.lower() in port.get("service", ".").lower():
               if hlight :
                  port["service"] = highlight(port["service"], value)
               matchedlist.append(data | port)
            elif  value.lower() in port.get("servicefp", ".").lower():
               if hlight :
                  port["servicefp"] = highlight(port["servicefp"], value)
               matchedlist.append(data | port)
            elif value.lower() in data.get("org", "."):
               if hlight :
                  port["org"] = highlight(port["org"], value)
               matchedlist.append(data | port)
               break
            elif value.lower() in data.get("isp", ".") :
               if hlight :
                  port["isp"] = highlight(port["isp"], value)
               matchedlist.append(data | port)
               break
         case "version":
            if value.lower() in port.get("version", ".").lower() :
               if hlight :
                  port["version"] = highlight(port["version"], value)
               matchedlist.append(data | port)
         case "product":
            if value.lower() in port.get("product", ".").lower() :
               if hlight :
                  port["product"] = highlight(port["product"], value)
               matchedlist.append(data | port)
         case "service":
            if value.lower() in port.get("service", ".").lower() :
               if hlight :
                  port["service"] = highlight(port["service"], value)
               matchedlist.append(data | port)
         case "info":
            if value.lower() in port.get("info", ".").lower() :
               if hlight :
                  port["info"] = highlight(port["info"], value)
               matchedlist.append(data | port)
         case "port" :
            if port["port"] == value:
               if hlight :
                  port["port"] = highlight(port["port"], value)
               matchedlist.append(data | port)
         case "cpe":
            for cpe in cpes :
               if value.lower() in cpe :
                  if hlight :
                     port["cpe"] = highlight(cpe, value)
                  matchedlist.append(data | port)
                  break
         case "os":
            if value.lower() in port.get("os", "").lower() and value :
               if hlight :
                  port["os"] = highlight(port["os"], value)
               matchedlist.append(data | port)
         case "country":
            matchedlist.append(data | port)
            if hlight :
               data["country"] = highlight(data["country"], data["country"])
            break
         case "isp":
            if hlight :
               port["isp"] = highlight(port["isp"], value)
            matchedlist.append(data | port)
            break
         case "city" :
            if hlight :
               port["city"] = highlight(port["city"], value)
            matchedlist.append(data | port)
            break
         case "org":
            if hlight :
               port["org"] = highlight(port["org"], value)
            matchedlist.append(data | port)
            break
         case "zip":
            if hlight :
               port["zip"] = highlight(port["zip"], value)
            matchedlist.append(data | port)
            break
         case "ip":
            matchedlist.append(data | port)
            #break # show all port if used ip filter
   return matchedlist


def dump_csv(writer:csv.writer, json:list, filters:dict, headers:list, progress:tqdm, no:int) -> None:
   table = []
   for data in json:
      for key, values in filters.items():
         for value in values :
            matchedlist = find_matched_port(key, value, data, False)
            for matched in matchedlist:
               matched["no"] = str(no)
               row = [ matched.get(head, "")  for head in headers ]
               table.append(row)
      no += 1
      progress.update(no)
   writer.writerows(table)


def print_results(json:list, filters:dict, headers:list, no:int) -> None:
   table = []
   tee   = "├  "
   elbow = "└───"
   for data in json:
      no += 1
      perfix = tee
      # for item inside ports []
      for key, values in filters.items():
         # for filter in input filters
         for value in values :
            matchedlist = find_matched_port(key, value, data, True)
            if matchedlist:
               for matched in matchedlist:
                  matched["no"] = perfix + str(no) if perfix == tee  else elbow
                  row = [ matched.get(head, "")  for head in headers ]
                  table.append(row)
                  perfix = elbow
   if table :
      print(tabulate(table, headers=headers))
   else:
      print("Not Found!")


def print_stats(stats:list, headers:list) -> None:
   table = [["", "Total" , f"{stats.pop('total'):,}"]]
   for category, branch  in stats.items() :
      table.append([category, "", ""])
      for n, (name, value) in enumerate(branch.items()):
         category = "└───"
         table.append([category, name, f"{value:,}"])
         if n == 5 : break
   print(tabulate(table, headers=["headers", "name", "value"]))


def print_message(code:int) -> None:
   match code :
      case 401:
         print("Unauthorized - Your API key is not valid or missing.")
      case 402:
         print("Payment Requierd - Service unavailable in current subscription")
      case 429:
         print("Too Many Requests - You have reached the maximum number of requests.")
      case 503:
         print("Service Unavailable - The service is currently unavailable. Please try again later.")
      case 500:
         print("Internal Server Error - We encountered an unexpected error while processing yourrequest.")
      case 504 :
         print("Gateway Timeout - The server did not receive a timely response from an upstream server.")
      case _:
         print(f"{code} - Unknown error please contact tech support")


def search(filters:tuple, page:int, size:int, headers:str) -> None:
   params = defaultdict(list)
   for filter in filters :
      key, value = filter.split(":")
      params[key].append(value)
   filters = dict(params)
   params = filters | dict(page=page, size=size, apikey=APIKEY)
   responce = requests.get(
      url="https://anytarget.io/api/search",
      params = params
      )
   no = (page-1) * size
   if responce.status_code == 200 :
      print_results(responce.json(), filters, headers.split(","), no)
   else:
      print_message(responce.status_code)


def stats(filters:tuple) -> None:
   params = defaultdict(list)
   for filter in filters :
      key, value = filter.split(":")
      params[key].append(value)
   params = dict(params) | dict(apikey=APIKEY)
   responce = requests.get(
      url="https://anytarget.io/api/stats",
      params = params
      )
   if responce.status_code == 200 :
      print_stats(responce.json(), [])
   else:
      print_message(responce.status_code)


def download(filters:tuple, headers:str, output:str, size:int) -> None:
   params = defaultdict(list)
   for filter in filters :
      key, value = filter.split(":")
      params[key].append(value)
   filters = dict(params)
   params = filters | dict(size=1000, apikey=APIKEY)
   headers = headers.split(",")
   csvfile = open(file=output, mode="w", newline="")
   responce = requests.get(
      url="https://anytarget.io/api/stats",
      params = params
   )
   if responce.status_code == 200 :
      stats = responce.json()
      size = stats["total"] if size == 0 else min(size, stats["total"])
      progress = tqdm(total=size, desc="Downloading", unit="ip", ncols=100)
      writer = csv.writer(csvfile)
      writer.writerow(headers)
      no, page = 0, 1
      # slicing requests size [1000, 1000, 1000, ... n<100]
      for size in ( ([1000] * int(size/1000)) + [size%1000] )  :
         params["page"] = page
         params["size"] = size
         responce = requests.get(
            url="https://anytarget.io/api/search",
            params = params
         )
         if responce.status_code == 200 :
            dump_csv(writer, responce.json(), filters, headers, progress, no)
         else:
            print(responce.status_code)
            break
         no   += size
         page += 1
   else:
      print_message(responce.status_code)

   csvfile.close()


def account():
   responce = requests.get(
      url= "https://anytarget.io/api/account",
      params = dict(apikey=APIKEY)
   )
   if responce.status_code == 200 :
      print(json.dumps(responce.json(), indent=3))
   else:
      print_message(responce.status_code)



########################################################

APIKEY = get_apikey()


# create cli #############################################

@click.group(context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def cli():
   """This is the main entry point for the CLI."""
   pass


helpPage = "Used to specify the desired page of results when using paginated search. It's often used in conjunction with 'size to segment results into pages, page = [1,2,3,n] -> results = [n*size] && skip = [n*size]"

helpSize = "The number of results retrieved in a single request. It determines the page size or the quantity the request should return."
helpSize2 = "The number of results downloaded use 0 to download all results."

helpPretty = "Determines whether the retrieved data will be displayed neatly and organized in the browser."

helpHeaders = "Each header is used to categorize and label the corresponding data columns in the output"

hDefault = "no,ip,port,service,product,version,os,cpe,script"

helpAPI = "It's used to access data or services provided by an API"


@cli.command(name="search")#, context_settings=opt)
@click.argument("filters", required=True, nargs=-1 )
@click.option("-p", "--page", type=int, default=1, help=helpPage)
@click.option("-s", "--size", type=int, default=10, help=helpSize)
@click.option("-h", "--headers", type=str, default=hDefault, help=helpHeaders)
def search_command(**kwargs):
   """Use the search command to retrieve specific results."""
   return search(**kwargs)

@cli.command(name="download")
@click.argument("filters", required=True, nargs=-1)
@click.option("-o","--output", required=True,  type=click.Path(), help="csv file output")
@click.option("-h", "--headers", type=str, default=hDefault, help=helpHeaders)
@click.option("-s","--size", required=False, type=int, default=10, help=helpSize2 )
def download_command(**kwargs):
   """Use the download command to export results into a CSV file."""
   return download(**kwargs)

@cli.command(name="stats")
@click.argument("filters", required=True, nargs=-1)
def stats_command(**kwargs):
   """Use the stats command to obtain statistical information about the results."""
   return stats(**kwargs)

@cli.command(name="init")
@click.argument("apikey", required=True, nargs=1)
def init_command(apikey):
   """Initialize/Update api-key"""
   return init(apikey)

@cli.command(name="account")
def account_command():
   """Show your account details"""
   return account()



if __name__ == "__main__":
   cli()


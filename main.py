import api.fetch as api

api.download_and_insert_recent()
print(api.fetch_one({
	"CVE_data_meta": {
		"CVE_ID": "CVE-2014-0097"
	}
}))

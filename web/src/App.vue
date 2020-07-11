<template>
  <div id="app">
    <div v-if="findings == null">
      Loading ....
    </div>
    <div v-else>
      <Title msg="Container CVE scan results" :updated="findings.updated_at"/>
      <div id="main">
        <div id="vulns">
          <h3>CRITICAL</h3>
          <li class="vuln_links" v-for="vuln in cves.CRITICAL"
              v-bind:key="vuln.cve.Name">
            <a v-bind:class="{ selected: isSelected(vuln.cve.Name) }" v-on:click="select(vuln.cve.Name)">{{ vuln.cve.Name }} ({{vuln.count}})</a>
          </li>
          <h3>HIGH</h3>
          <li class="vuln_links" v-for="vuln in cves.HIGH"
              v-bind:key="vuln.cve.Name">
            <a v-on:click="select(vuln.cve.Name)">{{ vuln.cve.Name }} ({{vuln.count}})</a>
          </li>
          <h3>Medium</h3>
          <li class="vuln_links" v-for="vuln in cves.MEDIUM"
              v-bind:key="vuln.cve.Name">
            <a v-on:click="select(vuln.cve.Name)">{{ vuln.cve.Name }} ({{vuln.count}})</a>
          </li>
          <li class="vuln_links" v-for="vuln in cves.LOW"
              v-bind:key="vuln.cve.Name">
            <a v-on:click="select(vuln.cve.Name)">{{ vuln.cve.Name }} ({{vuln.count}})</a>
          </li>
        </div>
        <div id="right_box">
          <div v-show="selected_cve" id="cve_details">
            <b>CVE:</b> {{ !findings.vulnerabilities[selected_cve] || findings.vulnerabilities[selected_cve].cve.Name }}<br />
            <a>
              <b>Severity:</b> {{ !findings.vulnerabilities[selected_cve] || findings.vulnerabilities[selected_cve].cve.Severity }}
            </a><br />
            <a>
              <b>Description:</b> {{ ! findings.vulnerabilities[selected_cve] || findings.vulnerabilities[selected_cve].cve.Description }}
            </a><br />
            <a v-bind:key="attr.Key" v-for="attr in selected_attrs">
              <b>{{ attr.Key }}:</b> {{ attr.Value }}<br/>
            </a>
            <br />
            <a :href="!findings.vulnerabilities[selected_cve] || findings.vulnerabilities[selected_cve].cve.Uri">Link to details</a>
          </div>
          <div id="account" v-for="account in accounts"
              v-bind:key="account.account_id">
            <Account v-bind:account="account" v-bind:selected_cve="selected_cve"></Account>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import Title from './components/Title.vue'
import Account from "./components/Account";
import * as axios from "axios";

var scve = null;
function select(name) {
  if (this.selected_cve === name) {
    this.selected_cve = null;
  } else {
    this.selected_cve = name;
  }
}

function isSelected(name) {
  return this.selected_cve === name;
}
function partitionCVEs(cves) {
  let categories = {};
  for (var name in cves) {
    let finding = cves[name];
    if (categories[finding.cve.Severity]) {
      categories[finding.cve.Severity].push(finding);
    } else {
      categories[finding.cve.Severity] = [finding];
    }
  }
  return categories;
}

function reduceImage(accumulator, image) {
  if (image.cves.indexOf(scve) >= 0 || scve == null) {
    return accumulator.concat(image)
  } else {
    return accumulator
  }
}


function reduceRepo(accumulator, repo) {
  if (repo.images == null) {
    return accumulator;
  }
  var images = repo.images.reduce(reduceImage, []);
  repo.images = images;
  if (images.length > 0) {
    return accumulator.concat(repo)
  } else {
    return accumulator
  }
}


function reduceRegion(accumulator, region) {
  if (region.repositories == null) {
    return accumulator;
  }
  var repos = region.repositories.reduce(reduceRepo, []);
  region.repositories = repos;
  if (repos.length > 0) {
    return accumulator.concat(region)
  } else {
    return accumulator
  }
}

function reduceAccount(accumulator, account) {
  if (account.regions == null) {
    return accumulator;
  }
  var regions = account.regions.reduce(reduceRegion, []);
  account.regions = regions;
  if (regions.length > 0) {
    return accumulator.concat(account)
  } else {
    return accumulator
  }
}

export default {
  name: 'App',
  components: {
    Title,
    Account
  },
  data() {
    return {
      selected_cve: null,
      select: select,
      findings: null,
      isSelected: isSelected
    }
  },
  mounted () {
    axios
      .get('/findings.json')
      .then(response => {
        console.log("Loaded");
        this.findings = response.data;
        console.log(this.findings);
      });
  },
  computed: {
    accounts: function() {
      if (!this.selected_cve) {
        scve = null;
        return JSON.parse(JSON.stringify(this.findings.accounts)).reduce(reduceAccount, []);
      } else {
        scve = this.selected_cve;
        return  JSON.parse(JSON.stringify(this.findings.accounts)).reduce(reduceAccount, []);
      }
    },
    cves: function() {
      let cs = partitionCVEs(this.findings.vulnerabilities);
      return cs;
    },
    selected_attrs: function() {
      if (this.findings.vulnerabilities[this.selected_cve] != null) {
        return this.findings.vulnerabilities[this.selected_cve].cve.Attributes
      } else {
        return []
      }
    }
  }
}
</script>

<style>
  #main {
    display: flex;
    border-top: 1px solid #eaecef;
  }
  #cve {
    font-size: 0.8em;
  }
  #cve_details {
    font-size: 0.9em;
    text-align: left;
    background: #eaecef;
    padding-top: 1%;
  }
  #right_box {
    width: 88%;

  }
  .selected {
    font-weight: bold;
  }
  #account {
    border-bottom: 1px solid #eaecef;
    padding-left: 1%;
  }
  #vulns {
    text-align: left;
    list-style: none;
    border-right: 1px solid #eaecef;
    width: 12%;
  }
  .vuln_links {
    text-decoration: underline;
  }
  #app {
    font-family: Avenir, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    color: #2c3e50;
  }
</style>

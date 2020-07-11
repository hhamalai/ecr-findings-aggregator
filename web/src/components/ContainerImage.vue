<template>
    <div>
        <span class="img_tag"><b>{{ image.tag }}</b></span> {{ cve_count }} known CVEs
        <button v-on:click="show_cves = !show_cves" v-show="!show_cves">details</button>
        <div v-show="show_cves">
            Image digest: {{ image.digest }}<br />
            CVEs: <a id="cve" v-for="cve in image.cves"
               v-bind:key="cve">
                <a>{{ cve }} </a>
            </a>
        </div>
    </div>
</template>

<script>

export default {
    name: 'ContainerImage',
    props: ['image', 'selected_cve'],
    data() {
        return {
            show_cves: false,
            show_digest: false,
        }
    },
    computed: {
        cve_count: function() {
            if (!this.image.cves) {
                return 0
            }
            return this.image.cves.length
        }
    }
}
</script>

<style>
    .img_tag {
        min-width: 100px;
        display: inline-block;
    }
</style>
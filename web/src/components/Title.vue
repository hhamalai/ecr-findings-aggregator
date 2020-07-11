<template>
  <div class="title">
    <h2>{{ msg }}</h2>
    Updated at: {{ updated }} UTC
  </div>
</template>

<script>

  export default {
    name: 'Title',
    props: {
      msg: String,
      updated: String
    }
}
</script>

<style scoped>
  h2 {
    margin-block-start: 0px;
    margin-block-end: 0px;
  }
  .title {
    margin: 0px;
    padding: 0px;
  }
</style>
